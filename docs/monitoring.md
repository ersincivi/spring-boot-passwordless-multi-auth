# Monitoring — Metrics, Grafana, Prometheus & Logs

Everything below ships with the repo and starts with one command:

```bash
./start-fullstack.sh
```

No accounts, no cloud — the whole stack runs in local Docker containers.

## What runs where

| Service | URL | What it is for |
|---|---|---|
| Application | <http://localhost:8585> | The Spring Boot app itself |
| Grafana | <http://localhost:3000> | Dashboards (pre-provisioned) |
| Prometheus | <http://localhost:9090> | Metrics collection & queries |
| Kibana | <http://localhost:5601> | Searching the structured logs |
| Mailpit | <http://localhost:8025> | Local test inbox — see [local-email-testing.md](local-email-testing.md) |
| pgAdmin | <http://localhost:5050> | Postgres UI |

Exporters for the infrastructure run alongside: node-exporter (host, `:9100`),
redis-exporter (`:9121`) and postgres-exporter (`:9187`), so the dashboards
show the database and cache too, not only the JVM.

## Metrics (Prometheus)

The app exposes metrics in Prometheus format at:

```
GET /actuator/prometheus
```

The endpoint is **not public** — Prometheus authenticates with a static Bearer
token. Set the same value in two places:

1. `MONITORING_TOKEN` in your `.env`
2. the git-ignored file `monitoring/monitoring-token`, which the scrape jobs
   read via `credentials_file`:

   ```bash
   printf '%s' "$MONITORING_TOKEN" > monitoring/monitoring-token
   ```

Besides the standard JVM/HTTP metrics, the app registers custom counters in
`config/MetricsConfig.java` — `application.login.attempts`,
`application.security.events`, database connection counts and active-session
gauges. These are what the Grafana authentication panels are built on.

## Dashboards (Grafana)

Grafana is pre-provisioned from `monitoring/grafana/`:

- the Prometheus datasource is configured automatically,
- the application dashboard (`dashboards/application-dashboard.json`) is
  loaded at startup — request rates, latencies, JVM memory, auth events,
  Redis and Postgres health.

First login uses the credentials from your `.env` (`GRAFANA_ADMIN_PASSWORD`).

## Logs (ELK)

The app writes structured logs (see `logback-spring.xml`); Filebeat ships the
Docker container logs to Logstash, which parses them with the grok patterns in
`logstash/patterns/app_patterns` — including a `SECURITY_EVENT` pattern that
extracts login failures, lockouts, rate-limit hits and suspicious-activity
markers into their own fields.

Useful starting points:

- `elk/predefined-queries.txt` — ready-made Kibana queries (failed logins by
  IP, lockout timeline, rate-limit spikes)
- `elk/alerting-rules.txt` — alerting rule suggestions to pair with them

Open Kibana at <http://localhost:5601>, create a data view for the
`logstash-*` index and paste any query from the file above.
