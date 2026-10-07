-- CovertScope database schema
-- PostgreSQL 14+

CREATE TABLE IF NOT EXISTS flows (
    id              BIGSERIAL PRIMARY KEY,
    flow_uid        BIGINT NOT NULL,
    src_ip          INET NOT NULL,
    src_port        INTEGER,
    dst_ip          INET NOT NULL,
    dst_port        INTEGER,
    l4_proto        VARCHAR(8),                 -- TCP / UDP / ICMP
    ndpi_protocol   VARCHAR(64),
    ndpi_proto_id   INTEGER,
    packets         INTEGER DEFAULT 0,
    bytes           BIGINT DEFAULT 0,
    duration_ms     INTEGER DEFAULT 0,

    -- timing features
    iat_mean        DOUBLE PRECISION,
    iat_variance    DOUBLE PRECISION,
    iat_cv          DOUBLE PRECISION,
    iat_autocorr1   DOUBLE PRECISION,

    -- entropy / payload features
    payload_entropy DOUBLE PRECISION,
    avg_pkt_len     DOUBLE PRECISION,

    -- DNS-specific
    dns_query       TEXT,
    dns_entropy     DOUBLE PRECISION,
    dns_qlen        INTEGER,
    dns_qps         DOUBLE PRECISION,

    -- HTTP-specific
    http_host       VARCHAR(255),
    http_user_agent TEXT,
    http_url        TEXT,
    http_ua_entropy DOUBLE PRECISION,

    -- ICMP-specific
    icmp_payload_len   INTEGER,
    icmp_payload_entropy DOUBLE PRECISION,

    covert_flags    INTEGER DEFAULT 0,
    anomaly_score   DOUBLE PRECISION DEFAULT 0,
    is_covert       BOOLEAN DEFAULT FALSE,
    blocked         BOOLEAN NOT NULL DEFAULT FALSE,  -- src or dst matched an active blocked_ips entry

    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_flows_created_at ON flows (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_flows_ndpi_protocol ON flows (ndpi_protocol);
CREATE INDEX IF NOT EXISTS idx_flows_is_covert ON flows (is_covert);
CREATE INDEX IF NOT EXISTS idx_flows_anomaly_score ON flows (anomaly_score DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id              BIGSERIAL PRIMARY KEY,
    flow_id         BIGINT REFERENCES flows(id) ON DELETE CASCADE,
    covert_type     VARCHAR(32) NOT NULL,       -- TIMING / DNS / HTTP / ICMP
    stat_score      DOUBLE PRECISION DEFAULT 0,
    ml_score        DOUBLE PRECISION DEFAULT 0,
    final_score     DOUBLE PRECISION NOT NULL,
    confidence      VARCHAR(16) NOT NULL,       -- CRITICAL / HIGH / MEDIUM / LOW
    reason          TEXT,
    recommendation  TEXT,
    acknowledged    BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_confidence ON alerts (confidence);
CREATE INDEX IF NOT EXISTS idx_alerts_covert_type ON alerts (covert_type);

-- Soft/advisory blocklist raised by an analyst from an alert or flow. See
-- the BlockedIP model docstring in backend/app/database.py for what this
-- table does and doesn't do (CovertScope is a passive monitor, not an
-- inline enforcement point).
CREATE TABLE IF NOT EXISTS blocked_ips (
    id              BIGSERIAL PRIMARY KEY,
    ip              VARCHAR(64) NOT NULL UNIQUE,
    reason          TEXT,
    alert_id        BIGINT REFERENCES alerts(id) ON DELETE SET NULL,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips (active);

CREATE TABLE IF NOT EXISTS thresholds (
    key             VARCHAR(64) PRIMARY KEY,
    value           DOUBLE PRECISION NOT NULL,
    description     TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO thresholds (key, value, description) VALUES
    ('entropy_high',        7.2,  'Payload Shannon entropy threshold (bits)'),
    ('dns_label_entropy',   3.8,  'DNS subdomain label entropy threshold'),
    ('dns_label_len',       60,   'DNS subdomain label length threshold (chars)'),
    ('dns_qps',             15,   'DNS queries-per-second threshold'),
    ('iat_cv_low',          0.05, 'IAT coefficient of variation - regularity threshold'),
    ('iat_autocorr',        0.80, 'IAT lag-1 autocorrelation threshold'),
    ('http_ua_entropy',     4.5,  'HTTP User-Agent entropy threshold'),
    ('http_url_entropy',    4.8,  'HTTP URL entropy threshold'),
    ('icmp_payload_len',    64,   'ICMP payload length threshold (bytes)'),
    ('icmp_payload_entropy',6.0,  'ICMP payload entropy threshold'),
    ('alert_score',         0.40, 'Minimum final_score to raise an alert'),
    ('ml_contamination',    0.05, 'Isolation Forest assumed contamination rate')
ON CONFLICT (key) DO NOTHING;
