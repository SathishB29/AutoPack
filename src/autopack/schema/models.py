"""Canonical typed schema models for AutoPack artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _to_iso8601(value: datetime) -> str:
    """Serialize a datetime in canonical UTC ISO-8601 format."""
    normalized = value.astimezone(timezone.utc)
    return normalized.isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str, field_name: str) -> datetime:
    """Parse datetimes in either Z or offset ISO-8601 form."""
    if not value:
        raise ValueError(
            f"{field_name} is required and must be a non-empty datetime string"
        )

    candidate = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be ISO-8601, got: {value!r}") from exc

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


@dataclass(slots=True)
class SourceFileManifest:
    """Source-level metadata tracked in a generated pack manifest."""

    source_type: str
    path: str
    sha256: str
    size_bytes: int
    event_count: int
    split_files: list[str] | None = None
    split_file_count: int | None = None

    def validate(self) -> None:
        if not self.source_type:
            raise ValueError("source_type must be non-empty")
        if not self.path:
            raise ValueError("path must be non-empty")
        if not self.sha256 or len(self.sha256) != 64:
            raise ValueError("sha256 must be a 64-character hexadecimal digest")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be >= 0")
        if self.event_count < 0:
            raise ValueError("event_count must be >= 0")
        if self.split_files is not None:
            if not self.split_files:
                raise ValueError("split_files must not be empty when provided")
            if any(not item for item in self.split_files):
                raise ValueError("split_files must contain non-empty paths")
        if self.split_file_count is not None:
            if self.split_file_count <= 0:
                raise ValueError("split_file_count must be > 0 when provided")
            if self.split_files is not None and self.split_file_count != len(
                self.split_files
            ):
                raise ValueError("split_file_count must match split_files length")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        payload: dict[str, Any] = {
            "source_type": self.source_type,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "event_count": self.event_count,
        }

        if self.split_files is not None:
            payload["split_files"] = list(self.split_files)
        if self.split_file_count is not None:
            payload["split_file_count"] = self.split_file_count

        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SourceFileManifest":
        raw_split_count = data.get("split_file_count")

        item = cls(
            source_type=str(data.get("source_type", "")),
            path=str(data.get("path", "")),
            sha256=str(data.get("sha256", "")),
            size_bytes=int(data.get("size_bytes", 0)),
            event_count=int(data.get("event_count", 0)),
            split_files=[str(item) for item in data.get("split_files", [])]
            if data.get("split_files") is not None
            else None,
            split_file_count=int(raw_split_count) if raw_split_count is not None else None,
        )
        item.validate()
        return item


@dataclass(slots=True)
class Manifest:
    """Top-level manifest for an investigation pack."""

    pack_version: str
    session_id: str
    created_at: datetime
    generator: str
    source_files: list[SourceFileManifest]
    total_events: int
    total_anomalies: int
    total_correlations: int
    parse_warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if not self.pack_version:
            raise ValueError("pack_version must be non-empty")
        if not self.session_id:
            raise ValueError("session_id must be non-empty")
        if not self.generator:
            raise ValueError("generator must be non-empty")
        if self.total_events < 0:
            raise ValueError("total_events must be >= 0")
        if self.total_anomalies < 0:
            raise ValueError("total_anomalies must be >= 0")
        if self.total_correlations < 0:
            raise ValueError("total_correlations must be >= 0")
        for source in self.source_files:
            source.validate()

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "pack_version": self.pack_version,
            "session_id": self.session_id,
            "created_at": _to_iso8601(self.created_at),
            "generator": self.generator,
            "source_files": [item.to_dict() for item in self.source_files],
            "total_events": self.total_events,
            "total_anomalies": self.total_anomalies,
            "total_correlations": self.total_correlations,
            "parse_warnings": list(self.parse_warnings),
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Manifest":
        item = cls(
            pack_version=str(data.get("pack_version", "")),
            session_id=str(data.get("session_id", "")),
            created_at=_parse_datetime(str(data.get("created_at", "")), "created_at"),
            generator=str(data.get("generator", "")),
            source_files=[
                SourceFileManifest.from_dict(part)
                for part in data.get("source_files", [])
                if isinstance(part, dict)
            ],
            total_events=int(data.get("total_events", 0)),
            total_anomalies=int(data.get("total_anomalies", 0)),
            total_correlations=int(data.get("total_correlations", 0)),
            parse_warnings=[str(item) for item in data.get("parse_warnings", [])],
            notes=[str(item) for item in data.get("notes", [])],
        )
        item.validate()
        return item


@dataclass(slots=True)
class NormalizedEvent:
    """Canonical normalized event shared across log and trace sources."""

    event_id: str
    timestamp: datetime
    source_type: str
    source_file: str
    message: str
    ecu: str | None = None
    app_id: str | None = None
    context_id: str | None = None
    bus_channel: str | None = None
    frame_id: str | None = None
    signal_name: str | None = None
    severity: str = "info"
    category: str = "generic"
    attributes: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    correlation_keys: dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.event_id:
            raise ValueError("event_id must be non-empty")
        if not self.source_type:
            raise ValueError("source_type must be non-empty")
        if not self.source_file:
            raise ValueError("source_file must be non-empty")
        if not self.message:
            raise ValueError("message must be non-empty")
        if not self.severity:
            raise ValueError("severity must be non-empty")
        if not self.category:
            raise ValueError("category must be non-empty")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "event_id": self.event_id,
            "timestamp": _to_iso8601(self.timestamp),
            "source_type": self.source_type,
            "source_file": self.source_file,
            "ecu": self.ecu,
            "app_id": self.app_id,
            "context_id": self.context_id,
            "bus_channel": self.bus_channel,
            "frame_id": self.frame_id,
            "signal_name": self.signal_name,
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "attributes": dict(self.attributes),
            "tags": list(self.tags),
            "correlation_keys": dict(self.correlation_keys),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NormalizedEvent":
        item = cls(
            event_id=str(data.get("event_id", "")),
            timestamp=_parse_datetime(str(data.get("timestamp", "")), "timestamp"),
            source_type=str(data.get("source_type", "")),
            source_file=str(data.get("source_file", "")),
            ecu=_optional_text(data.get("ecu")),
            app_id=_optional_text(data.get("app_id")),
            context_id=_optional_text(data.get("context_id")),
            bus_channel=_optional_text(data.get("bus_channel")),
            frame_id=_optional_text(data.get("frame_id")),
            signal_name=_optional_text(data.get("signal_name")),
            severity=str(data.get("severity", "info")),
            category=str(data.get("category", "generic")),
            message=str(data.get("message", "")),
            attributes=_safe_dict(data.get("attributes")),
            tags=[str(tag) for tag in data.get("tags", [])],
            correlation_keys={
                str(k): str(v)
                for k, v in _safe_dict(data.get("correlation_keys")).items()
            },
        )
        item.validate()
        return item


@dataclass(slots=True)
class Anomaly:
    """Structured anomaly emitted from deterministic detection logic."""

    anomaly_id: str
    kind: str
    severity: str
    start_time: datetime
    end_time: datetime
    event_ids: list[str]
    evidence_sources: list[str]
    description: str
    score: float | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.anomaly_id:
            raise ValueError("anomaly_id must be non-empty")
        if not self.kind:
            raise ValueError("kind must be non-empty")
        if not self.severity:
            raise ValueError("severity must be non-empty")
        if not self.description:
            raise ValueError("description must be non-empty")
        if self.end_time < self.start_time:
            raise ValueError("end_time must be >= start_time")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "anomaly_id": self.anomaly_id,
            "kind": self.kind,
            "severity": self.severity,
            "start_time": _to_iso8601(self.start_time),
            "end_time": _to_iso8601(self.end_time),
            "event_ids": list(self.event_ids),
            "evidence_sources": list(self.evidence_sources),
            "description": self.description,
            "score": self.score,
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Anomaly":
        raw_score = data.get("score")
        score = float(raw_score) if raw_score is not None else None
        item = cls(
            anomaly_id=str(data.get("anomaly_id", "")),
            kind=str(data.get("kind", "")),
            severity=str(data.get("severity", "")),
            start_time=_parse_datetime(str(data.get("start_time", "")), "start_time"),
            end_time=_parse_datetime(str(data.get("end_time", "")), "end_time"),
            event_ids=[str(event_id) for event_id in data.get("event_ids", [])],
            evidence_sources=[
                str(source) for source in data.get("evidence_sources", [])
            ],
            description=str(data.get("description", "")),
            score=score,
            attributes=_safe_dict(data.get("attributes")),
        )
        item.validate()
        return item


@dataclass(slots=True)
class Correlation:
    """Cross-source evidence linkage over a bounded time window."""

    correlation_id: str
    rule: str
    confidence: float
    window_start: datetime
    window_end: datetime
    event_ids: list[str]
    source_types: list[str]
    summary: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.correlation_id:
            raise ValueError("correlation_id must be non-empty")
        if not self.rule:
            raise ValueError("rule must be non-empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in range [0.0, 1.0]")
        if self.window_end < self.window_start:
            raise ValueError("window_end must be >= window_start")
        if not self.summary:
            raise ValueError("summary must be non-empty")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "correlation_id": self.correlation_id,
            "rule": self.rule,
            "confidence": self.confidence,
            "window_start": _to_iso8601(self.window_start),
            "window_end": _to_iso8601(self.window_end),
            "event_ids": list(self.event_ids),
            "source_types": list(self.source_types),
            "summary": self.summary,
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Correlation":
        item = cls(
            correlation_id=str(data.get("correlation_id", "")),
            rule=str(data.get("rule", "")),
            confidence=float(data.get("confidence", 0.0)),
            window_start=_parse_datetime(
                str(data.get("window_start", "")), "window_start"
            ),
            window_end=_parse_datetime(str(data.get("window_end", "")), "window_end"),
            event_ids=[str(event_id) for event_id in data.get("event_ids", [])],
            source_types=[
                str(source_type) for source_type in data.get("source_types", [])
            ],
            summary=str(data.get("summary", "")),
            attributes=_safe_dict(data.get("attributes")),
        )
        item.validate()
        return item


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None
