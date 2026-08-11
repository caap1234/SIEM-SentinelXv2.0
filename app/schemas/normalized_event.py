# app/schemas/normalized_event.py
"""
Esquema Canónico Unificado de Eventos para SentinelX SIEM (v1.0.0).
Compatible conceptualmente con Elastic Common Schema (ECS) y OCSF.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict, field_validator


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SchemaMeta(BaseModel):
    name: str = Field(default="sentinelx-ecs", description="Nombre del esquema canónico")
    version: str = Field(default="1.0.0", description="Versión del esquema")


class EventMeta(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="ID único global del evento")
    kind: str = Field(default="event", description="event | alert | metric | state")
    category: List[str] = Field(default_factory=lambda: ["network"], description="Categoría(s) ECS (e.g., mail, web, authentication, malware)")
    type: List[str] = Field(default_factory=lambda: ["info"], description="Tipo(s) de evento (e.g., access, allowed, denied, error)")
    action: Optional[str] = Field(default=None, description="Acción específica (e.g., smtp_auth_login, http_request)")
    outcome: str = Field(default="unknown", description="success | failure | unknown")
    severity: int = Field(default=1, ge=0, le=100, description="Nivel de severidad (0-100)")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Puntuación de riesgo acumulado (0.0 - 100.0)")
    dataset: str = Field(default="generic", description="Dataset específico (e.g., exim.mainlog, apache.access)")
    module: str = Field(default="hosting", description="Módulo de origen (e.g., hosting, network, security)")
    original: Optional[str] = Field(default=None, description="Línea o payload original de evidencia")


class TenantMeta(BaseModel):
    id: str = Field(default="default", description="ID obligatorio del Tenant (Unidad de aislamiento principal)")


class HostingContext(BaseModel):
    customer_id: Optional[str] = Field(default=None, description="ID del cliente comercial de hosting")
    reseller_id: Optional[str] = Field(default=None, description="ID del reseller/revendedor")
    account_id: Optional[str] = Field(default=None, description="Cuenta de cPanel / DirectAdmin relacionada")
    domain_name: Optional[str] = Field(default=None, description="Dominio de la cuenta de hosting")


class HostMeta(BaseModel):
    id: Optional[str] = Field(default=None, description="Identificador único del host")
    name: str = Field(default="unknown-host", description="Nombre asignado al host")
    hostname: Optional[str] = Field(default=None, description="Hostname del sistema operativo")
    ip: Optional[str] = Field(default=None, description="IP primaria del host")
    os_name: Optional[str] = Field(default=None, description="AlmaLinux | CloudLinux | Ubuntu | RHEL")
    os_version: Optional[str] = Field(default=None, description="Versión del SO")


class AgentMeta(BaseModel):
    id: Optional[str] = Field(default=None, description="ID único del agente SentinelX")
    name: Optional[str] = Field(default=None, description="Nombre del agente")
    version: Optional[str] = Field(default="1.0.0", description="Versión del agente")


class ServiceMeta(BaseModel):
    name: str = Field(default="system", description="exim | dovecot | apache | nginx | modsecurity | csf | cphulk | sshd")
    type: Optional[str] = Field(default=None, description="Tipo de servicio (mail | web | firewall | security | auth)")


class SourceMeta(BaseModel):
    ip: Optional[str] = Field(default=None, description="IP de origen (canonical source.ip)")
    port: Optional[int] = Field(default=None, ge=0, le=65535, description="Puerto de origen")
    geo_country_iso_code: Optional[str] = Field(default=None, description="Código ISO de país GeoIP (e.g., US, MX)")
    as_number: Optional[int] = Field(default=None, description="Número de ASN GeoIP")
    as_organization_name: Optional[str] = Field(default=None, description="Nombre de la organización ASN")


class DestinationMeta(BaseModel):
    ip: Optional[str] = Field(default=None, description="IP de destino")
    port: Optional[int] = Field(default=None, ge=0, le=65535, description="Puerto de destino")


class NetworkMeta(BaseModel):
    transport: Optional[str] = Field(default=None, description="tcp | udp | icmp")
    protocol: Optional[str] = Field(default=None, description="http | https | smtp | imap | pop3 | ssh | dns")
    bytes: Optional[int] = Field(default=None, ge=0, description="Bytes transmitidos")
    packets: Optional[int] = Field(default=None, ge=0, description="Paquetes transmitidos")


class UserMeta(BaseModel):
    id: Optional[str] = Field(default=None, description="ID único de usuario")
    name: Optional[str] = Field(default=None, description="Nombre de usuario autenticado o ejecutante")
    domain: Optional[str] = Field(default=None, description="Dominio del usuario")


class ProcessMeta(BaseModel):
    pid: Optional[int] = Field(default=None, description="PID del proceso")
    name: Optional[str] = Field(default=None, description="Nombre del proceso (e.g., php-fpm, exim, httpd)")
    executable: Optional[str] = Field(default=None, description="Ruta al ejecutable")
    command_line: Optional[str] = Field(default=None, description="Línea de comando completa")


class FileMeta(BaseModel):
    path: Optional[str] = Field(default=None, description="Ruta completa al archivo")
    name: Optional[str] = Field(default=None, description="Nombre del archivo")
    extension: Optional[str] = Field(default=None, description="Extensión (.php, .sh, .py)")
    size: Optional[int] = Field(default=None, ge=0, description="Tamaño del archivo en bytes")
    hash_sha256: Optional[str] = Field(default=None, description="Hash SHA-256 del archivo")


class UrlMeta(BaseModel):
    original: Optional[str] = Field(default=None, description="URL completa solicitada")
    path: Optional[str] = Field(default=None, description="Ruta URI (e.g., /wp-login.php)")
    query: Optional[str] = Field(default=None, description="Query string (e.g., ?action=login)")
    domain: Optional[str] = Field(default=None, description="Host/Dominio de la URL")


class HttpMeta(BaseModel):
    method: Optional[str] = Field(default=None, description="GET | POST | PUT | DELETE | HEAD | OPTIONS")
    status_code: Optional[int] = Field(default=None, ge=100, le=599, description="Código HTTP (e.g., 200, 403, 500)")
    referrer: Optional[str] = Field(default=None, description="Referer HTTP")


class EmailMeta(BaseModel):
    from_address: Optional[str] = Field(default=None, description="Dirección remitente (From)")
    to_address: Optional[str] = Field(default=None, description="Dirección destinatario (To)")
    subject: Optional[str] = Field(default=None, description="Asunto del correo")
    message_id: Optional[str] = Field(default=None, description="Message-ID del encabezado SMTP")
    queue_id: Optional[str] = Field(default=None, description="Exim Queue ID (e.g., 1a2b3c-4d5e6f-7g)")
    authenticated_user: Optional[str] = Field(default=None, description="Usuario autenticado en la sesión SMTP")


class RuleMeta(BaseModel):
    id: Optional[str] = Field(default=None, description="ID de la regla de detección gatillada")
    name: Optional[str] = Field(default=None, description="Nombre de la regla")
    category: Optional[str] = Field(default=None, description="Categoría de la regla")
    version: Optional[str] = Field(default=None, description="Versión de la regla")


class LogMeta(BaseModel):
    level: Optional[str] = Field(default=None, description="info | warn | error | debug | fatal")
    file_path: Optional[str] = Field(default=None, description="Ruta del archivo de log monitoreado")
    offset: Optional[int] = Field(default=None, ge=0, description="Offset en bytes")
    original: Optional[str] = Field(default=None, description="Línea cruda original")


class MetricMeta(BaseModel):
    """
    Extensión canónica propia de SentinelX para métricas numéricas de rendimiento (ECS Custom Extension).
    Garantiza tipado estricto float/int para agregaciones y consultas de rango en OpenSearch.
    """
    family: Optional[str] = Field(default=None, description="Familia de métricas (e.g., sar, system)")
    name: Optional[str] = Field(default=None, description="Nombre específico de la métrica (e.g., load, memory, disk)")
    cpu_count: Optional[int] = Field(default=None, description="Número de núcleos de CPU")
    runq_sz: Optional[float] = Field(default=None, description="Procesos en cola de ejecución (runq-sz)")
    plist_sz: Optional[float] = Field(default=None, description="Procesos totales en lista (plist-sz)")
    blocked: Optional[float] = Field(default=None, description="Procesos bloqueados en I/O (blocked)")
    ldavg_1: Optional[float] = Field(default=None, description="Carga promedio CPU a 1 min (ldavg_1)")
    ldavg_5: Optional[float] = Field(default=None, description="Carga promedio CPU a 5 min (ldavg_5)")
    ldavg_15: Optional[float] = Field(default=None, description="Carga promedio CPU a 15 min (ldavg_15)")
    ldavg_1_per_cpu: Optional[float] = Field(default=None, description="Carga a 1 min normalizada por núcleo de CPU")
    ldavg_5_per_cpu: Optional[float] = Field(default=None, description="Carga a 5 min normalizada por núcleo de CPU")
    ldavg_15_per_cpu: Optional[float] = Field(default=None, description="Carga a 15 min normalizada por núcleo de CPU")
    kb_mem_free: Optional[int] = Field(default=None, description="Memoria RAM libre en KB")
    kb_mem_used: Optional[int] = Field(default=None, description="Memoria RAM usada en KB")
    kb_mem_avail: Optional[int] = Field(default=None, description="Memoria RAM disponible en KB")
    mem_used_pct: Optional[float] = Field(default=None, description="Porcentaje de uso de memoria RAM (0.0 - 100.0)")
    device: Optional[str] = Field(default=None, description="Dispositivo de disco (e.g., sda, sdb, nvme0n1)")
    tps: Optional[float] = Field(default=None, description="Transacciones por segundo en disco")
    util_pct: Optional[float] = Field(default=None, description="Porcentaje de utilización I/O de disco")


class NormalizedEvent(BaseModel):
    """
    Contrato Canónico Oficial de Eventos de SentinelX-SIEM (ECS-compliant).
    """
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    timestamp_utc: datetime = Field(default_factory=_utc_now, alias="@timestamp", description="Timestamp UTC ISO 8601 del evento")
    sentinelx_schema: SchemaMeta = Field(default_factory=SchemaMeta, alias="schema", description="Metadatos del esquema SentinelX")

    event: EventMeta = Field(default_factory=EventMeta)
    tenant: TenantMeta = Field(default_factory=TenantMeta)
    customer: HostingContext = Field(default_factory=HostingContext)

    host: HostMeta = Field(default_factory=HostMeta)
    agent: AgentMeta = Field(default_factory=AgentMeta)
    service: ServiceMeta = Field(default_factory=ServiceMeta)

    source: SourceMeta = Field(default_factory=SourceMeta)
    destination: DestinationMeta = Field(default_factory=DestinationMeta)
    network: NetworkMeta = Field(default_factory=NetworkMeta)

    user: UserMeta = Field(default_factory=UserMeta)
    process: ProcessMeta = Field(default_factory=ProcessMeta)
    file: FileMeta = Field(default_factory=FileMeta)

    url: UrlMeta = Field(default_factory=UrlMeta)
    http: HttpMeta = Field(default_factory=HttpMeta)
    email: EmailMeta = Field(default_factory=EmailMeta)

    rule: RuleMeta = Field(default_factory=RuleMeta)
    log: LogMeta = Field(default_factory=LogMeta)
    metric: MetricMeta = Field(default_factory=MetricMeta, description="Métricas numéricas de sistema (SAR)")

    labels: Dict[str, str] = Field(default_factory=dict, description="Etiquetas clave-valor adicionales")
    tags: List[str] = Field(default_factory=list, description="Lista de tags")

    @field_validator("timestamp_utc", mode="before")
    @classmethod
    def ensure_utc_timezone(cls, v: Any) -> datetime:
        if isinstance(v, str):
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        elif isinstance(v, datetime):
            dt = v
        else:
            dt = datetime.now(timezone.utc)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def to_opensearch_doc(self) -> Dict[str, Any]:
        """Convierte el evento normalizado a documento JSON compatible con OpenSearch."""
        data = self.model_dump(by_alias=True)
        # Formatear @timestamp como ISO 8601 estricto
        if isinstance(self.timestamp_utc, datetime):
            data["@timestamp"] = self.timestamp_utc.isoformat()
        return data
