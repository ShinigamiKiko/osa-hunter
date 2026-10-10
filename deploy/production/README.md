# Production behind an external HTTPS proxy

OSA listens on `127.0.0.1:3000`. The external nginx/Ingress terminates TLS and forwards to this listener. Direct external access to the internal HTTP listener must stay closed. A same-host nginx can use the example below. For an Ingress running on another host or in Kubernetes, use an internal service/network restricted to that Ingress instead of publishing the HTTP port publicly.

Generate independent credentials once:

```bash
node scripts/init-env.cjs
docker compose -f docker-compose.yml -f docker-compose.production.yml up --build -d
```

The helper creates `.env` with mode `0600`, unique database/admin passwords and a persistent session secret. It does not print credentials or overwrite an existing file. Keep this file in your secret store and reuse it after restart. Edit `OSA_NEXUS_REPOSITORIES`, `NEXUS_UPSTREAM` and any private-registry credentials for your contour before routing package-manager traffic through OSA. Do not commit `.env`.

Production requires `SESSION_SECRET` (at least 32 characters), `PGPASSWORD` (at least 16), `ADMIN_PASSWORD` (12 to 72 UTF-8 bytes), `HTTPS=true`, and secure cookies. Example/default passwords are rejected. The production Compose override forces the production mode, HTTPS and secure cookies. The internal nginx forwards a fixed HTTPS scheme; it does not trust a client-supplied `X-Forwarded-Proto`. The backend trusts only the frontend as its immediate reverse proxy. The external proxy must overwrite X-Forwarded-For with the actual client IP (as in the example), so per-IP limits remain effective and client-supplied addresses are discarded.

Example external nginx configuration; replace the hostname and certificate paths with your own trusted certificate:

```nginx
server {
    listen 80;
    server_name osa.example.com;
    return 308 https://osa.example.com$request_uri;
}

server {
    listen 443 ssl;
    server_name osa.example.com;
    ssl_certificate /etc/letsencrypt/live/osa.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/osa.example.com/privkey.pem;

    client_max_body_size 16m;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 660s;
        proxy_send_timeout 660s;
    }
}
```

Use your public HTTPS address to sign in. The login cookie is `__Host-osa.sid` with `Secure`, `HttpOnly`, `SameSite=Lax`, and `Path=/`. A plain HTTP browser cannot use that cookie. PostgreSQL is not published and uses password authentication. Metrics/backend ports stay on localhost.

## Existing databases

`ADMIN_PASSWORD` seeds a fresh database; it does not reset an existing user's password. Production refuses an existing administrator whose password is the development default `admin`. Change that password through the account UI/admin reset before switching modes, or start with a separate production database. Changing `PGPASSWORD` in `.env` does not rotate the password in an existing PostgreSQL volume. Rotate the database role password with your database administration workflow and update the secret together. Do not delete a volume to rotate credentials.

Keep the current database volume and `.env` on restart. Back up and test restoration of PostgreSQL separately. CISA reachability depends on your VPN/egress; policy remains fail-closed when required security data is unavailable.
