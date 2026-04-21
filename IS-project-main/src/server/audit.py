from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from time import time
from typing import Any


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_type: str
    outcome: str
    details: dict[str, Any]
    timestamp: float = field(default_factory=time)


@dataclass(slots=True)
class AuditLogger:
    log_path: str | None = None
    _events: list[AuditEvent] = field(default_factory=list)

    def record(self, event_type: str, outcome: str, **details: Any) -> AuditEvent:
        event = AuditEvent(event_type=event_type, outcome=outcome, details=details)
        self._events.append(event)

        if self.log_path is not None:
            target = Path(self.log_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(
                {
                    "timestamp": event.timestamp,
                    "event_type": event.event_type,
                    "outcome": event.outcome,
                    "details": event.details,
                },
                sort_keys=True,
            )
            target.write_text(
                (target.read_text(encoding="utf-8") if target.exists() else "") + line + "\n",
                encoding="utf-8",
            )
        return event

    def list_events(self) -> list[AuditEvent]:
        return list(self._events)
