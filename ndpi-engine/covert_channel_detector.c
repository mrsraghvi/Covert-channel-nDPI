/*
 * CovertScope — nDPI-based covert channel detector
 *
 * Captures live traffic (or reads a pcap file), classifies every flow with
 * nDPI, tracks per-flow inter-arrival-time (IAT) statistics and payload
 * entropy, and streams a JSON record per completed/idle flow to the
 * Python backend over a plain TCP socket (default 127.0.0.1:9999), which
 * runs it through the statistical + ML detectors and persists it.
 *
 * This engine only performs read-only packet inspection: it does not
 * inject, modify, or forward any traffic.
 *
 * Build:
 *   make ndpi     # builds/uses ../ndpi-engine/nDPI-dev
 *   make          # builds covert_detector
 *
 * Run (root / CAP_NET_RAW+CAP_NET_ADMIN required for live capture):
 *   sudo ./covert_detector eth0 ["bpf filter"]
 *   ./covert_detector -r capture.pcap        (offline mode, no root needed)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>

#define BACKEND_HOST      "127.0.0.1"
#define BACKEND_PORT      9999
/* Shared secret for the ingest socket, read from the environment at
 * startup (COVERTSCOPE_INGEST_SECRET). Must match the value the backend
 * was started with (see backend/app/engine.py). If unset, no AUTH line is
 * sent — fine for an isolated single-host lab setup where the backend's
 * COVERTSCOPE_INGEST_SECRET is also unset, but anyone who can reach the
 * port can then inject fake flow records. */
static const char *g_ingest_secret = NULL;
static int g_authenticated = 0;
#define MAX_FLOWS         65536
#define FLOW_IDLE_MS      15000   /* export + evict after 15s of silence */
#define IAT_SAMPLE_MAX    64      /* ring buffer of inter-arrival samples */
#define PAYLOAD_SAMPLE_MAX 512    /* bytes sampled per flow for entropy   */
#define ETH_HDR_LEN       14
#define IPV4_HEADER_MIN   20
#define IPV6_HEADER_LEN   40

/* ------------------------------------------------------------------ */
/* Per-flow tracking state (on top of nDPI's own flow struct)         */
/* ------------------------------------------------------------------ */
typedef struct flow_info {
    int in_use;
    uint64_t flow_id;

    /* 5-tuple */
    uint8_t ip_version;
    uint8_t src_ip[16], dst_ip[16];
    uint16_t src_port, dst_port;
    uint8_t  l4_proto;   /* IPPROTO_TCP / UDP / ICMP */

    struct ndpi_flow_struct *ndpi_flow;
    ndpi_protocol detected_protocol;

    uint64_t first_seen_ms, last_seen_ms;
    uint32_t packets;
    uint64_t bytes;

    double   iat_samples[IAT_SAMPLE_MAX];
    int      iat_count;

    unsigned char payload_sample[PAYLOAD_SAMPLE_MAX];
    int      payload_sample_len;

    /* ICMP */
    int      icmp_payload_len;

    int      exported;
} flow_info_t;

static flow_info_t g_flows[MAX_FLOWS];
static uint64_t g_flow_id_counter = 0;
static struct ndpi_detection_module_struct *g_ndpi = NULL;
static int g_sock = -1;
static volatile sig_atomic_t g_stop = 0;
static uint64_t g_total_packets = 0;

static void on_sigint(int sig) { (void)sig; g_stop = 1; }

/* ------------------------------------------------------------------ */
/* Backend socket (line-delimited JSON)                               */
/* ------------------------------------------------------------------ */
static int connect_backend(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void send_line(const char *json) {
    if (g_sock < 0) {
        g_sock = connect_backend(BACKEND_HOST, BACKEND_PORT);
        if (g_sock < 0) {
            fprintf(stderr, "[warn] backend not reachable on %s:%d (will retry)\n",
                    BACKEND_HOST, BACKEND_PORT);
            return;
        }
        g_authenticated = 0;

        if (g_ingest_secret) {
            char auth_buf[512];
            int an = snprintf(auth_buf, sizeof(auth_buf), "AUTH %s\n", g_ingest_secret);
            if (an <= 0 || (size_t)an >= sizeof(auth_buf) || write(g_sock, auth_buf, an) < 0) {
                fprintf(stderr, "[error] failed to send ingest AUTH line\n");
                close(g_sock);
                g_sock = -1;
                return;
            }
        }
        g_authenticated = 1;
    }
    if (!g_authenticated) return;

    char buf[4096];
    int n = snprintf(buf, sizeof(buf), "%s\n", json);
    if (write(g_sock, buf, n) < 0) {
        close(g_sock);
        g_sock = -1; /* reconnect next time */
    }
}

/* ------------------------------------------------------------------ */
/* Math helpers                                                       */
/* ------------------------------------------------------------------ */
static double shannon_entropy(const unsigned char *data, int len) {
    if (len <= 0) return 0.0;
    int counts[256] = {0};
    for (int i = 0; i < len; i++) counts[data[i]]++;
    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / len;
        h -= p * log2(p);
    }
    return h;
}

static void iat_stats(const double *samples, int n, double *mean, double *var,
                       double *cv, double *autocorr1) {
    *mean = *var = *cv = *autocorr1 = 0.0;
    if (n < 2) return;
    double sum = 0;
    for (int i = 0; i < n; i++) sum += samples[i];
    *mean = sum / n;
    double sq = 0;
    for (int i = 0; i < n; i++) sq += (samples[i] - *mean) * (samples[i] - *mean);
    *var = sq / n;
    if (*mean > 0) *cv = sqrt(*var) / *mean;

    if (n >= 3 && *var > 0) {
        double num = 0;
        for (int i = 0; i < n - 1; i++)
            num += (samples[i] - *mean) * (samples[i + 1] - *mean);
        *autocorr1 = num / (*var * n);
    }
}

static double iat_bimodal_ratio(const double *samples, int n) {
    if (n < 4) return 0.0;

    double sorted[IAT_SAMPLE_MAX];
    memcpy(sorted, samples, (size_t)n * sizeof(*sorted));
    for (int i = 1; i < n; i++) {
        double value = sorted[i];
        int j = i - 1;
        while (j >= 0 && sorted[j] > value) {
            sorted[j + 1] = sorted[j];
            j--;
        }
        sorted[j + 1] = value;
    }

    int tail = n / 8;
    if (tail < 1) tail = 1;
    double low = sorted[n / 8];
    double high = sorted[n - tail];
    if (high == low) return 0.0;

    double span = high - low;
    int near_clusters = 0;
    for (int i = 0; i < n; i++) {
        if (fabs(samples[i] - low) <= 0.15 * span ||
            fabs(samples[i] - high) <= 0.15 * span)
            near_clusters++;
    }
    return (double)near_clusters / n;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

/* ------------------------------------------------------------------ */
/* Flow table (linear-probe hash on the 5-tuple)                      */
/* ------------------------------------------------------------------ */
static uint32_t flow_hash(const uint8_t *sip, const uint8_t *dip, uint8_t ip_version,
                          uint16_t sp, uint16_t dp, uint8_t proto) {
    uint32_t h = 2166136261u;
    size_t addr_len = ip_version == 4 ? 4 : 16;
    for (size_t i = 0; i < addr_len; i++) {
        h = (h ^ sip[i]) * 16777619u;
        h = (h ^ dip[i]) * 16777619u;
    }
    h = (h ^ ip_version) * 16777619u;
    h ^= ((uint32_t)sp << 16 | dp) ^ proto;
    return h % MAX_FLOWS;
}

static flow_info_t *flow_lookup_or_create(const uint8_t *sip, const uint8_t *dip,
                                           uint8_t ip_version, uint16_t sp,
                                           uint16_t dp, uint8_t proto, int *is_new) {
    size_t addr_len = ip_version == 4 ? 4 : 16;
    uint32_t idx = flow_hash(sip, dip, ip_version, sp, dp, proto);
    for (uint32_t probe = 0; probe < MAX_FLOWS; probe++) {
        uint32_t i = (idx + probe) % MAX_FLOWS;
        flow_info_t *f = &g_flows[i];
        if (f->in_use && f->ip_version == ip_version &&
            memcmp(f->src_ip, sip, addr_len) == 0 &&
            memcmp(f->dst_ip, dip, addr_len) == 0 &&
            f->src_port == sp && f->dst_port == dp && f->l4_proto == proto) {
            *is_new = 0;
            return f;
        }
        if (!f->in_use) {
            memset(f, 0, sizeof(*f));
            f->in_use = 1;
            f->flow_id = ++g_flow_id_counter;
            f->ip_version = ip_version;
            memcpy(f->src_ip, sip, addr_len);
            memcpy(f->dst_ip, dip, addr_len);
            f->src_port = sp; f->dst_port = dp;
            f->l4_proto = proto;
            f->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(
                ndpi_detection_get_sizeof_ndpi_flow_struct());
            if (f->ndpi_flow)
                memset(f->ndpi_flow, 0, ndpi_detection_get_sizeof_ndpi_flow_struct());
            *is_new = 1;
            return f;
        }
    }
    *is_new = 0;
    return NULL; /* table full — extremely unlikely at 64k flows */
}

static const char *proto_name(ndpi_protocol p) {
    static char buf[64];
    ndpi_protocol2name(g_ndpi, p.proto, buf, sizeof(buf));
    return buf;
}

static const char *l4_name(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_ICMPV6: return "ICMP";
        default:           return "OTHER";
    }
}

static void ip_to_str(uint8_t ip_version, const uint8_t *ip, char *out, size_t outlen) {
    int family = ip_version == 4 ? AF_INET : AF_INET6;
    if (!inet_ntop(family, ip, out, (socklen_t)outlen))
        out[0] = '\0';
}

/* Export a flow record as JSON and send to the backend */
static void export_flow(flow_info_t *f) {
    if (f->exported) return;
    f->exported = 1;

    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    char src_endpoint[INET6_ADDRSTRLEN + 10], dst_endpoint[INET6_ADDRSTRLEN + 10];
    ip_to_str(f->ip_version, f->src_ip, src_ip, sizeof(src_ip));
    ip_to_str(f->ip_version, f->dst_ip, dst_ip, sizeof(dst_ip));
    if (f->ip_version == 6) {
        snprintf(src_endpoint, sizeof(src_endpoint), "[%s]:%u", src_ip, f->src_port);
        snprintf(dst_endpoint, sizeof(dst_endpoint), "[%s]:%u", dst_ip, f->dst_port);
    } else {
        snprintf(src_endpoint, sizeof(src_endpoint), "%s:%u", src_ip, f->src_port);
        snprintf(dst_endpoint, sizeof(dst_endpoint), "%s:%u", dst_ip, f->dst_port);
    }

    double mean, var, cv, ac1;
    iat_stats(f->iat_samples, f->iat_count, &mean, &var, &cv, &ac1);
    double iat_bimodal = iat_bimodal_ratio(f->iat_samples, f->iat_count);

    double payload_entropy = shannon_entropy(f->payload_sample, f->payload_sample_len);
    uint32_t duration_ms = (uint32_t)(f->last_seen_ms - f->first_seen_ms);

    const char *pname = f->ndpi_flow ? proto_name(f->detected_protocol) : "Unknown";

    /* nDPI stores shared host metadata in the flow core and HTTP fields in
       flow metadata. */
    const char *host = (f->ndpi_flow && f->ndpi_flow->core.host_server_name)
                            ? f->ndpi_flow->core.host_server_name : "";
    double dns_entropy = 0.0;
    int dns_qlen = 0;
    if (strstr(pname, "DNS") && host[0]) {
        /* entropy over the left-most (subdomain) label, where tunnel data lives */
        char label[256]; strncpy(label, host, sizeof(label) - 1); label[sizeof(label)-1]=0;
        char *dot = strchr(label, '.');
        if (dot) *dot = 0;
        dns_qlen = (int)strlen(host);
        dns_entropy = shannon_entropy((unsigned char *)label, (int)strlen(label));
    }

    const char *http_ua = "";
    const char *http_url = "";
    double http_ua_entropy = 0.0;
    if (f->ndpi_flow && f->ndpi_flow->metadata.http.user_agent) {
        http_ua = f->ndpi_flow->metadata.http.user_agent;
        http_ua_entropy = shannon_entropy((unsigned char *)http_ua, (int)strlen(http_ua));
    }
    if (f->ndpi_flow && f->ndpi_flow->metadata.http.url) {
        http_url = f->ndpi_flow->metadata.http.url;
    }

    double icmp_entropy = 0.0;
    if (f->l4_proto == IPPROTO_ICMP && f->payload_sample_len > 0)
        icmp_entropy = payload_entropy;

    char json[4096];
    snprintf(json, sizeof(json),
        "{"
        "\"type\":\"flow\",\"flow_id\":%llu,"
        "\"src\":\"%s\",\"dst\":\"%s\","
        "\"protocol\":\"%s\",\"ndpi_proto_id\":%u,\"l4_proto\":\"%s\","
        "\"packets\":%u,\"bytes\":%llu,\"duration_ms\":%u,"
        "\"iat_mean\":%.3f,\"iat_variance\":%.3f,\"iat_cv\":%.4f,\"iat_autocorr1\":%.4f,\"iat_bimodal\":%.4f,"
        "\"payload_entropy\":%.3f,"
        "\"dns_query\":\"%s\",\"dns_entropy\":%.3f,\"dns_qlen\":%d,"
        "\"http_host\":\"%s\",\"http_user_agent\":\"%s\",\"http_url\":\"%s\",\"http_ua_entropy\":%.3f,"
        "\"icmp_payload_len\":%d,\"icmp_payload_entropy\":%.3f,"
        "\"covert_flags\":0,\"ts\":%llu"
        "}",
        (unsigned long long)f->flow_id, src_endpoint, dst_endpoint,
        pname, f->detected_protocol.proto.master_protocol, l4_name(f->l4_proto),
        f->packets, (unsigned long long)f->bytes, duration_ms,
        mean, var, cv, ac1, iat_bimodal,
        payload_entropy,
        host, dns_entropy, dns_qlen,
        host, http_ua, http_url, http_ua_entropy,
        f->icmp_payload_len, icmp_entropy,
        (unsigned long long)now_ms());

    send_line(json);
}

/* Sweep the flow table and export/evict anything idle */
static void sweep_idle_flows(void) {
    uint64_t now = now_ms();
    for (int i = 0; i < MAX_FLOWS; i++) {
        flow_info_t *f = &g_flows[i];
        if (f->in_use && (now - f->last_seen_ms) > FLOW_IDLE_MS) {
            export_flow(f);
            if (f->ndpi_flow) { ndpi_free_flow_data(f->ndpi_flow); ndpi_flow_free(f->ndpi_flow); }
            memset(f, 0, sizeof(*f));
        }
    }
}

/* ------------------------------------------------------------------ */
/* Packet callback                                                    */
/* ------------------------------------------------------------------ */
static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    (void)user;
    g_total_packets++;

    if (hdr->caplen < ETH_HDR_LEN) return;

    uint16_t ethertype = ntohs(*(uint16_t *)(pkt + 12));
    const u_char *ip_pkt = pkt + ETH_HDR_LEN;
    uint32_t captured_ip_len = hdr->caplen - ETH_HDR_LEN;
    uint32_t ip_len, l4_len;
    uint8_t ip_version, proto;
    uint8_t src_ip[16] = {0}, dst_ip[16] = {0};
    const u_char *l4;

    if (ethertype == 0x0800) {
        if (captured_ip_len < IPV4_HEADER_MIN || (ip_pkt[0] >> 4) != 4) return;
        uint8_t ihl = (ip_pkt[0] & 0x0F) * 4;
        if (ihl < IPV4_HEADER_MIN || captured_ip_len < ihl) return;
        uint16_t total_len;
        memcpy(&total_len, ip_pkt + 2, sizeof(total_len));
        total_len = ntohs(total_len);
        if (total_len < ihl || captured_ip_len < total_len) return;
        ip_version = 4;
        ip_len = total_len;
        proto = ip_pkt[9];
        memcpy(src_ip, ip_pkt + 12, 4);
        memcpy(dst_ip, ip_pkt + 16, 4);
        l4 = ip_pkt + ihl;
        l4_len = total_len - ihl;
    } else if (ethertype == 0x86DD) {
        if (captured_ip_len < IPV6_HEADER_LEN || (ip_pkt[0] >> 4) != 6) return;
        uint16_t payload_len;
        memcpy(&payload_len, ip_pkt + 4, sizeof(payload_len));
        payload_len = ntohs(payload_len);
        uint32_t total_len = IPV6_HEADER_LEN + (uint32_t)payload_len;
        if (captured_ip_len < total_len) return;
        ip_version = 6;
        ip_len = total_len;
        proto = ip_pkt[6];
        memcpy(src_ip, ip_pkt + 8, 16);
        memcpy(dst_ip, ip_pkt + 24, 16);
        l4 = ip_pkt + IPV6_HEADER_LEN;
        l4_len = payload_len;

        for (int extensions = 0; extensions < 8; extensions++) {
            uint32_t extension_len;
            if (proto == 0 || proto == 43 || proto == 60 || proto == 135) {
                if (l4_len < 2) return;
                extension_len = ((uint32_t)l4[1] + 1) * 8;
            } else if (proto == 44) {
                if (l4_len < 8) return;
                uint16_t fragment;
                memcpy(&fragment, l4 + 2, sizeof(fragment));
                if (ntohs(fragment) & 0xFFF9) return;
                extension_len = 8;
            } else if (proto == 51) {
                if (l4_len < 2) return;
                extension_len = ((uint32_t)l4[1] + 2) * 4;
            } else {
                break;
            }
            if (extension_len > l4_len) return;
            proto = l4[0];
            l4 += extension_len;
            l4_len -= extension_len;
        }
        if (proto == 0 || proto == 43 || proto == 44 || proto == 51 ||
            proto == 60 || proto == 135)
            return;
    } else {
        return;
    }

    uint16_t src_port = 0, dst_port = 0;
    const u_char *payload = l4;
    uint32_t payload_len = l4_len;

    if (proto == IPPROTO_TCP && l4_len >= 20) {
        memcpy(&src_port, l4, 2); src_port = ntohs(src_port);
        memcpy(&dst_port, l4 + 2, 2); dst_port = ntohs(dst_port);
        uint8_t data_off = ((l4[12] >> 4) & 0x0F) * 4;
        payload = l4 + data_off;
        payload_len = (l4_len > data_off) ? l4_len - data_off : 0;
    } else if (proto == IPPROTO_UDP && l4_len >= 8) {
        memcpy(&src_port, l4, 2); src_port = ntohs(src_port);
        memcpy(&dst_port, l4 + 2, 2); dst_port = ntohs(dst_port);
        payload = l4 + 8;
        payload_len = (l4_len > 8) ? l4_len - 8 : 0;
    } else if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
        payload = l4 + 8; /* skip icmp type/code/checksum/id/seq */
        payload_len = (l4_len > 8) ? l4_len - 8 : 0;
    }

    int is_new;
    flow_info_t *f = flow_lookup_or_create(src_ip, dst_ip, ip_version,
                                            src_port, dst_port, proto, &is_new);
    if (!f) return;

    uint64_t pkt_ms = (uint64_t)hdr->ts.tv_sec * 1000ULL + hdr->ts.tv_usec / 1000ULL;
    if (is_new) {
        f->first_seen_ms = pkt_ms;
    } else if (f->last_seen_ms) {
        double iat = (double)(pkt_ms - f->last_seen_ms);
        if (f->iat_count < IAT_SAMPLE_MAX) f->iat_samples[f->iat_count++] = iat;
    }
    f->last_seen_ms = pkt_ms;
    f->packets++;
    f->bytes += hdr->len;

    if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6)
        f->icmp_payload_len = (int)payload_len;

    /* sample payload bytes for entropy (cap to keep this O(1) per packet) */
    if (payload_len > 0 && f->payload_sample_len < PAYLOAD_SAMPLE_MAX) {
        int copy = payload_len;
        if (f->payload_sample_len + copy > PAYLOAD_SAMPLE_MAX)
            copy = PAYLOAD_SAMPLE_MAX - f->payload_sample_len;
        memcpy(f->payload_sample + f->payload_sample_len, payload, copy);
        f->payload_sample_len += copy;
    }

    if (f->ndpi_flow && f->detected_protocol.proto.master_protocol == 0) {
        f->detected_protocol = ndpi_detection_process_packet(
            g_ndpi, f->ndpi_flow, ip_pkt, (uint16_t)ip_len,
            pkt_ms, NULL);
    }

    if ((g_total_packets & 0x3FF) == 0) sweep_idle_flows(); /* periodic sweep */
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = NULL;
    const char *iface = NULL, *pcap_file = NULL, *bpf = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) pcap_file = argv[++i];
        else if (!iface) iface = argv[i];
        else if (!bpf) bpf = argv[i];
    }

    if (!iface && !pcap_file) {
        fprintf(stderr, "Usage: %s <interface> [\"bpf filter\"]\n"
                         "       %s -r <file.pcap>\n", argv[0], argv[0]);
        return 1;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    g_ingest_secret = getenv("COVERTSCOPE_INGEST_SECRET");
    if (!g_ingest_secret || !g_ingest_secret[0]) {
        fprintf(stderr,
            "[warn] COVERTSCOPE_INGEST_SECRET not set — connecting to the "
            "backend without authentication. Set it (matching the backend's "
            "env var of the same name) for anything beyond an isolated "
            "single-host lab setup.\n");
        g_ingest_secret = NULL;
    }

    g_ndpi = ndpi_init_detection_module(NULL, NDPI_LICENSE_FOR_PROFIT_LGPL);
    if (!g_ndpi) { fprintf(stderr, "ndpi_init_detection_module failed\n"); return 1; }
    if (ndpi_finalize_initialization(g_ndpi) != 0) {
        fprintf(stderr, "ndpi_finalize_initialization failed\n"); return 1;
    }

    if (pcap_file) {
        pcap = pcap_open_offline(pcap_file, errbuf);
    } else {
        pcap = pcap_open_live(iface, 65535, 1, 1000, errbuf);
    }
    if (!pcap) {
        fprintf(stderr, "pcap open failed: %s\n", errbuf);
        return 1;
    }

    if (bpf) {
        struct bpf_program fp;
        if (pcap_compile(pcap, &fp, bpf, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(pcap, &fp);
            pcap_freecode(&fp);
        } else {
            fprintf(stderr, "[warn] bpf filter compile failed: %s\n", pcap_geterr(pcap));
        }
    }

    fprintf(stderr, "CovertScope nDPI engine running on %s -> exporting to %s:%d\n",
            pcap_file ? pcap_file : iface, BACKEND_HOST, BACKEND_PORT);

    while (!g_stop) {
        int rc = pcap_dispatch(pcap, 256, packet_handler, NULL);
        if (rc == 0 && pcap_file) break;  /* EOF on offline capture */
        if (rc < 0) break;                /* error or pcap_breakloop */
    }

    /* flush remaining flows */
    for (int i = 0; i < MAX_FLOWS; i++)
        if (g_flows[i].in_use) export_flow(&g_flows[i]);

    pcap_close(pcap);
    if (g_sock >= 0) close(g_sock);
    ndpi_exit_detection_module(g_ndpi);
    fprintf(stderr, "\nCovertScope engine stopped. %llu packets processed.\n",
            (unsigned long long)g_total_packets);
    return 0;
}
