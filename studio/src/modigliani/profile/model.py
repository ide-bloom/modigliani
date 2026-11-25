"""The Modigliani device profile (schema version 1).

A profile is everything the generic server needs to stand in for a vendor cloud: names
to answer, handlers with response templates, auth emulation, the state model, command
encodings and Home Assistant mappings. Every inferred element carries evidence.

Template strings use `{{ expr }}`; a string that is exactly one expression keeps the
expression's JSON type. See docs/profile-schema.md for the expression reference.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

SCHEMA_VERSION = 1


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Evidence(_Model):
    capture: str
    flow: int
    message: int


class Fingerprint(_Model):
    kind: Literal["sni", "dns_name", "http_user_agent", "mqtt_client_id", "coap_path", "port"]
    pattern: str = Field(description="Regular expression (RE2-compatible)")
    evidence: list[Evidence] = Field(default_factory=list)


class HostReport(_Model):
    host: str
    port: int
    tls_outcome: str
    flows: int
    bytes_up: int
    bytes_down: int
    first_seen: float
    last_seen: float
    mean_interval_s: float | None = None


class Revivability(_Model):
    status: Literal["revivable", "partial", "not_revivable_without_firmware_access"]
    reasons: list[str] = Field(default_factory=list)
    hosts: list[HostReport] = Field(default_factory=list)


class DeviceInfo(_Model):
    vendor: str = "unknown"
    model: str = "unknown"
    description: str = ""
    fingerprints: list[Fingerprint] = Field(default_factory=list)


class DnsConfig(_Model):
    names: list[str] = Field(default_factory=list)
    ttl: int = 60


class TlsConfig(_Model):
    mode: Literal["none", "local_ca", "strict_verification", "mixed"] = "none"
    hostnames: list[str] = Field(default_factory=list)


class PlaceholderSource(_Model):
    """Where `modigliani install` finds this value in the user's own capture."""

    kind: Literal[
        "http_path",
        "http_body",
        "http_header",
        "mqtt_client_id",
        "mqtt_username",
        "mqtt_topic",
        "coap_path",
    ]
    handler: str | None = None
    selector: str = ""
    pattern: str | None = None


class Placeholder(_Model):
    kind: Literal["device_id", "serial", "mac", "account", "token", "key", "ssid", "ip", "secret", "other"]
    description: str = ""
    value: JsonValue = None
    source: PlaceholderSource | None = None


class TokenSpec(_Model):
    format: Literal["hex", "base64url", "uuid", "jwt", "alnum", "numeric"]
    length: int = 32
    prefix: str = ""
    lifetime_s: int | None = None
    location: Literal["bearer", "header", "query", "body"] = "bearer"
    name: str = "Authorization"
    issued_by: str = Field(description="id of the HTTP handler that issues tokens")
    evidence: list[Evidence] = Field(default_factory=list)


class MqttAuth(_Model):
    client_id_pattern: str = ""
    username_pattern: str = ""
    # The server cannot know the vendor's secrets, so it accepts the device's own password.
    password: Literal["accept_any"] = "accept_any"


class AuthConfig(_Model):
    token: TokenSpec | None = None
    mqtt: MqttAuth | None = None
    notes: list[str] = Field(default_factory=list)


class Extract(_Model):
    """Copy a value from an incoming message into a reported state variable."""

    source: str = Field(description="Expression such as req.body.power or req.fields.temp")
    variable: str
    scale: float | None = None
    value_map: dict[str, JsonValue] | None = Field(
        default=None, description="Device value (as JSON text) -> state value"
    )


class HttpResponseSpec(_Model):
    status: int = 200
    headers: dict[str, str] = Field(default_factory=dict)
    body_type: Literal["json", "form", "text", "empty"] = "json"
    body: JsonValue = None


class CommandDelivery(_Model):
    """How pending commands are embedded into a polled response."""

    mode: Literal["list", "replace"] = "list"
    path: str = Field(description="Dotted path in the response body; '' for the whole body")


class HttpHandler(_Model):
    id: str
    host: str | None = None
    method: str
    path: str = Field(description="Path template; {name} segments are parameters")
    identity: str | None = Field(default=None, description="Expression giving the device key")
    auth: Literal["none", "issue_token", "token"] = "none"
    extract: list[Extract] = Field(default_factory=list)
    request_schema: dict[str, JsonValue] | None = None
    response: HttpResponseSpec = Field(default_factory=HttpResponseSpec)
    delivers_commands: CommandDelivery | None = None
    housekeeping: Literal["time_sync", "firmware_check"] | None = None
    polling_interval_s: float | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class WsMessageRule(_Model):
    id: str
    match: dict[str, JsonValue] = Field(default_factory=dict)
    extract: list[Extract] = Field(default_factory=list)
    reply: JsonValue = None
    evidence: list[Evidence] = Field(default_factory=list)


class WebSocketHandler(_Model):
    id: str
    host: str | None = None
    path: str
    identity: str | None = None
    messages: list[WsMessageRule] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class MqttTopic(_Model):
    id: str
    topic: str = Field(description="Topic template; {name} segments are variables")
    direction: Literal["device_to_cloud", "cloud_to_device"]
    qos: int = 0
    retain: bool = False
    payload_type: Literal["json", "text", "binary"] = "json"
    payload_schema: dict[str, JsonValue] | None = None
    extract: list[Extract] = Field(default_factory=list)
    # For cloud_to_device topics that answer a device request (e.g. time sync).
    reply_to: str | None = None
    payload: JsonValue = None
    housekeeping: Literal["time_sync", "firmware_check"] | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class MqttConfig(_Model):
    hosts: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    tls: bool = False
    protocol_levels: list[int] = Field(default_factory=lambda: [4])
    keepalive_s: int | None = None
    identity_var: str | None = None
    topics: list[MqttTopic] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class FrameField(_Model):
    name: str
    offset: int
    type: Literal["u8", "i8", "u16be", "u16le", "i16be", "i16le", "u32be", "u32le", "i32be", "i32le"]
    scale: float = 1.0
    const: int | None = None


class LengthField(_Model):
    offset: int
    type: Literal["u8", "u16be", "u16le", "u32be", "u32le"]
    adjust: int = Field(description="frame length = field value + adjust")


class Checksum(_Model):
    algorithm: Literal["sum8", "xor8", "crc8", "sum16", "crc16_ccitt", "crc16_modbus", "crc32"]
    offset: int = Field(description="Position of the checksum; negative counts from the end")
    start: int = 0
    end: int = Field(default=0, description="Exclusive end of covered bytes; <=0 counts from the end")
    endian: Literal["big", "little"] = "big"


class Frame(_Model):
    id: str
    length: int | None = None
    fields: list[FrameField] = Field(default_factory=list)
    length_field: LengthField | None = None
    checksum: Checksum | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class FramePayload(_Model):
    frame: str
    values: dict[str, JsonValue] = Field(default_factory=dict, description="field -> template")


class CoapResponseSpec(_Model):
    code: str = "2.05"
    content_format: int | None = None
    payload_type: Literal["empty", "json", "text", "frame"] = "empty"
    payload: JsonValue = None
    frame: FramePayload | None = None


class CoapHandler(_Model):
    id: str
    method: str
    path: str
    identity: str | None = None
    request_frame: str | None = None
    extract: list[Extract] = Field(default_factory=list)
    response: CoapResponseSpec = Field(default_factory=CoapResponseSpec)
    housekeeping: Literal["time_sync", "firmware_check"] | None = None
    polling_interval_s: float | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class Framing(_Model):
    kind: Literal["datagram", "length_prefixed", "delimiter", "fixed"]
    delimiter: str | None = Field(default=None, description="hex bytes")
    length_field: LengthField | None = None
    record_size: int | None = None


class RawRule(_Model):
    id: str
    match: dict[str, int] = Field(default_factory=dict, description="frame field -> required value")
    frame: str
    extract: list[Extract] = Field(default_factory=list)
    reply: FramePayload | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class RawHandler(_Model):
    id: str
    transport: Literal["tcp", "udp"]
    port: int
    host: str | None = None
    framing: Framing
    identity: str | None = None
    rules: list[RawRule] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class Handlers(_Model):
    http: list[HttpHandler] = Field(default_factory=list)
    websocket: list[WebSocketHandler] = Field(default_factory=list)
    mqtt: MqttConfig | None = None
    coap: list[CoapHandler] = Field(default_factory=list)
    raw: list[RawHandler] = Field(default_factory=list)


class StateVariable(_Model):
    name: str
    type: Literal["bool", "int", "float", "enum", "string"]
    unit: str | None = None
    min: float | None = None
    max: float | None = None
    step: float | None = None
    options: list[JsonValue] = Field(default_factory=list)
    writable: bool = False
    description: str = ""
    evidence: list[Evidence] = Field(default_factory=list)


class Command(_Model):
    name: str
    variable: str
    transport: Literal["http_poll", "mqtt", "coap_response", "websocket", "raw"]
    handler: str = Field(description="id of the HTTP handler, MQTT topic, CoAP/WS/raw handler")
    template: JsonValue = Field(default=None, description="Item/payload template; uses cmd.*")
    value_map: dict[str, JsonValue] | None = Field(
        default=None, description="State value (as JSON text) -> device value"
    )
    scale: float | None = Field(default=None, description="device value = state value / scale")
    evidence: list[Evidence] = Field(default_factory=list)


class HaEntity(_Model):
    platform: Literal["climate", "switch", "light", "sensor", "binary_sensor", "select", "number"]
    key: str
    name: str
    variable: str | None = None
    unit: str | None = None
    device_class: str | None = None
    state_class: str | None = None
    min: float | None = None
    max: float | None = None
    step: float | None = None
    options: list[str] = Field(default_factory=list)
    # climate
    current_temperature: str | None = None
    target_temperature: str | None = None
    hvac_mode: str | None = None
    hvac_mode_map: dict[str, str] = Field(default_factory=dict, description="device value -> HA mode")
    hvac_action: str | None = None


class HomeAssistant(_Model):
    entities: list[HaEntity] = Field(default_factory=list)


class Housekeeping(_Model):
    time_source: Literal["system", "offset"] = "system"
    time_offset_s: float = 0.0
    firmware: Literal["no_update"] = "no_update"


class Defaults(_Model):
    http: HttpResponseSpec = Field(default_factory=lambda: HttpResponseSpec(status=200, body={}))
    coap_code: str = "2.05"


class CaptureRef(_Model):
    name: str
    sha256: str
    mode: str


class Provenance(_Model):
    generated_by: str
    created: str
    captures: list[CaptureRef] = Field(default_factory=list)
    author: str | None = None
    license: Literal["CC0-1.0", "CC-BY-4.0"] | None = None
    scrubbed: bool = False
    notes: list[str] = Field(default_factory=list)


class Profile(_Model):
    schema_version: Literal[1] = 1
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]*$")
    name: str
    device: DeviceInfo = Field(default_factory=DeviceInfo)
    revivability: Revivability
    dns: DnsConfig = Field(default_factory=DnsConfig)
    tls: TlsConfig = Field(default_factory=TlsConfig)
    placeholders: dict[str, Placeholder] = Field(default_factory=dict)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    state: list[StateVariable] = Field(default_factory=list)
    commands: list[Command] = Field(default_factory=list)
    frames: list[Frame] = Field(default_factory=list)
    handlers: Handlers = Field(default_factory=Handlers)
    housekeeping: Housekeeping = Field(default_factory=Housekeeping)
    defaults: Defaults = Field(default_factory=Defaults)
    home_assistant: HomeAssistant = Field(default_factory=HomeAssistant)
    provenance: Provenance

    def variable(self, name: str) -> StateVariable | None:
        return next((v for v in self.state if v.name == name), None)

    def frame(self, frame_id: str) -> Frame | None:
        return next((f for f in self.frames if f.id == frame_id), None)
