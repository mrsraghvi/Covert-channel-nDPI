# Enforcing HTTPS

`docker-compose.yml` serves plain HTTP/WS — fine for the localhost-only lab
setup in `launch.md`, not fine the moment this is reachable from anywhere
else. This isn't something the backend/frontend containers should do
themselves (see SECURITY.md: no TLS termination baked in on purpose); it
belongs in a reverse proxy in front of them. Two ready-to-use options:

## Option A — Caddy (simplest: automatic cert + HTTP→HTTPS redirect)

```caddyfile
# Caddyfile
covertscope.yourdomain.example {
    reverse_proxy /api/* localhost:8000
    reverse_proxy /ws localhost:8000
    reverse_proxy /* localhost:3000
}
```

```bash
caddy run --config Caddyfile
```

Caddy gets a cert from Let's Encrypt automatically and redirects HTTP to
HTTPS by default — nothing else to configure for the "enforce HTTPS" part.

## Option B — nginx + certbot

```nginx
server {
    listen 80;
    server_name covertscope.yourdomain.example;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name covertscope.yourdomain.example;

    ssl_certificate     /etc/letsencrypt/live/covertscope.yourdomain.example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/covertscope.yourdomain.example/privkey.pem;

    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
    }
    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    location / {
        proxy_pass http://localhost:3000;
    }
}
```

## Don't forget, either way

- Update `CORS_ORIGINS` in `.env` to your real `https://` origin.
- The frontend's WS/API base-URL logic in `src/lib/api.js` already derives
  `wss://`/`https://` from `window.location.protocol` for anything that
  isn't `localhost:3000` — no code change needed there once you're serving
  through the proxy's real domain.
- Don't add `Strict-Transport-Security` (HSTS) until you're confident TLS
  is working end-to-end and will stay up — an HSTS header a browser caches
  and then can't reach over HTTPS locks users out, including you.
