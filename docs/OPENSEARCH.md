# Operación y Gestión de OpenSearch - SentinelX SIEM

## 1. Mappings y Data Streams

El SIEM utiliza el Data Stream `sentinelx-events-hosting-default` (patrón: `sentinelx-events-*`).

### Campos Principales Indexados:
- `@timestamp`: `date`
- `source.ip` / `destination.ip` / `host.ip`: `ip`
- `event.severity` / `http.status_code` / `source.port`: `integer`
- `event.risk_score`: `float`
- `user.name` / `customer.account_id` / `customer.domain_name`: `keyword`

---

## 2. Verificación de Salud y Plantillas

```bash
# Estado del Clúster
curl http://localhost:9200/_cluster/health?pretty

# Ver Index Templates
curl http://localhost:9200/_index_template/sentinelx-events-template?pretty

# Ver Políticas ISM
curl http://localhost:9200/_plugins/_ism/policies/sentinelx-retention-policy?pretty

# Buscar eventos en el Data Stream
curl http://localhost:9200/sentinelx-events-hosting-default/_search?pretty
```
