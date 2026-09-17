from forensic_assistant.detections.models import Rule


class EventObservation(Rule):
    def __init__(self, rule_id, name, event_id, kind, severity="low"):
        super().__init__(rule_id, name, "Review the recorded " + name.casefold(), severity, "1", (kind,))
        object.__setattr__(self, "event_id", event_id)

    def evaluate(self, db, event, parameters):
        if event["event_id"] == self.event_id:
            return self.observation(event, f"Provider-qualified Event ID {self.event_id} records {self.name.casefold()}")


RULES = [
    EventObservation("LOCARD-TASK-001", "Scheduled task creation", 4698, "scheduled_task"),
    EventObservation("LOCARD-SVC-001", "Service installation", 4697, "service"),
    EventObservation("LOCARD-AUDIT-001", "Audit log cleared", 1102, "audit_log_cleared", "medium"),
    EventObservation("LOCARD-ACCOUNT-001", "New user account created", 4720, "account_creation"),
    EventObservation("LOCARD-CRED-001", "Explicit credential use", 4648, "explicit_credentials"),
]
