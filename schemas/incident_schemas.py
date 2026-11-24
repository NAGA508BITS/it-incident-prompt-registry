from enum import Enum
from typing import Literal
from pydantic import BaseModel, Field, model_validator


class Environment(str, Enum):
    PROD = "prod"
    STAGING = "staging"
    DEV = "dev"


class Severity(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class IncidentCategory(str, Enum):
    SERVICE_OUTAGE = "service_outage"
    DEGRADED_PERFORMANCE = "degraded_performance"
    AUTH_OR_ACCESS = "auth_or_access"
    DATA_PIPELINE = "data_pipeline"
    CONFIG_OR_DEPLOY = "config_or_deploy"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Role 1: incident_parser
# ---------------------------------------------------------------------------
class IncidentParserInput(BaseModel):
    ticket_id: str = Field(pattern=r"^INC-\d{4,8}$")
    environment: Environment
    reported_by_role: str = Field(min_length=2, max_length=100)
    raw_description: str = Field(min_length=10, max_length=4000)


class ExtractedSignal(BaseModel):
    service_name: str = Field(min_length=2, max_length=120)
    error_code: str | None = Field(default=None, max_length=80)
    error_message: str = Field(min_length=5, max_length=300)
    timestamp_utc: str | None = Field(default=None, max_length=40)


class IncidentParserOutput(BaseModel):
    ticket_id: str = Field(pattern=r"^INC-\d{4,8}$")
    environment: Environment
    impacted_users_estimate: int | None = Field(default=None, ge=0, le=10_000_000)
    signals: list[ExtractedSignal] = Field(min_length=1, max_length=10)
    deployment_or_change_ref: str | None = Field(default=None, max_length=80)
    is_out_of_scope_or_injection: bool = False


# ---------------------------------------------------------------------------
# Role 2: severity_router
# ---------------------------------------------------------------------------
class SeverityRouterInput(BaseModel):
    parsed_incident: IncidentParserOutput
    raw_description: str = Field(min_length=10, max_length=4000)


class SeverityRouterOutput(BaseModel):
    ticket_id: str = Field(pattern=r"^INC-\d{4,8}$")
    category: IncidentCategory
    severity: Severity
    target_team: str = Field(min_length=2, max_length=80)
    confidence: float = Field(ge=0.0, le=1.0)
    routing_rationale: str = Field(min_length=20, max_length=500)

    @model_validator(mode="after")
    def validate_prod_p1_routing(self) -> "SeverityRouterOutput":
        if self.severity == Severity.P1 and self.target_team.lower() in {"none", "unassigned", "support-l1"}:
            raise ValueError("P1 incidents cannot be routed to 'none', 'unassigned', or 'support-l1'.")
        return self


# ---------------------------------------------------------------------------
# Role 3: sla_policy_checker
# ---------------------------------------------------------------------------
class SlaPolicyInput(BaseModel):
    environment: Environment
    category: IncidentCategory
    severity: Severity
    target_team: str = Field(min_length=2, max_length=80)
    impacted_users_estimate: int | None = Field(default=None, ge=0, le=10_000_000)


class PolicyDecision(BaseModel):
    escalation_team: str | None = Field(default=None, max_length=80)
    response_sla_minutes: int = Field(ge=5, le=1440)
    resolution_target_hours: int = Field(ge=1, le=168)
    auto_mitigation_allowed: bool
    requires_incident_commander: bool


class SlaPolicyOutput(BaseModel):
    ticket_id: str = Field(pattern=r"^INC-\d{4,8}$")
    policy: PolicyDecision
    policy_notes: str = Field(min_length=15, max_length=500)

    @model_validator(mode="after")
    def enforce_p1_sla_rules(self) -> "SlaPolicyOutput":
        if self.policy.requires_incident_commander and not self.policy.escalation_team:
            raise ValueError("escalation_team is mandatory when requires_incident_commander is True.")
        if self.policy.response_sla_minutes > 15 and self.policy.requires_incident_commander:
            raise ValueError("Incident-commander escalations must have response_sla_minutes <= 15.")
        return self


# ---------------------------------------------------------------------------
# Role 4: rca_brief_generator
# ---------------------------------------------------------------------------
class ActionItem(BaseModel):
    action: str = Field(min_length=10, max_length=250)
    owner_role: str = Field(min_length=2, max_length=80)
    priority: Literal["immediate", "short_term", "preventive"]


class RfcBriefInput(BaseModel):
    ticket_id: str = Field(pattern=r"^INC-\d{4,8}$")
    environment: Environment
    category: IncidentCategory
    severity: Severity
    signals: list[ExtractedSignal] = Field(min_length=1, max_length=10)
    policy: PolicyDecision


class RfcBriefOutput(BaseModel):
    ticket_id: str = Field(pattern=r"^INC-\d{4,8}$")
    headline: str = Field(min_length=10, max_length=180)
    impact_summary: str = Field(min_length=20, max_length=500)
    probable_root_cause: str = Field(min_length=15, max_length=500)
    mitigation_status: Literal["mitigated", "in_progress", "pending_escalation", "blocked_by_policy"]
    action_items: list[ActionItem] = Field(min_length=1, max_length=6)