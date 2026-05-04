"""Deterministic bus trace parsing helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Any

_FRAME_ID_RE = re.compile(r"(?:\bID\s*[:=]\s*)?(0x[0-9A-Fa-f]+)")
_BYTE_SEQUENCE_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})+)\b")
_TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)


@dataclass(slots=True)
class ParsedBusFrame:
    """Parsed bus frame fields for normalized event generation."""

    line_number: int
    timestamp: datetime | None
    channel: str | None
    frame_id: str | None
    arbitration_id: int | None
    data_hex: str | None
    message: str
    decoded_signals: dict[str, Any]


def parse_bus_trace(
    path: Path,
    *,
    dbc_path: Path | None = None,
) -> tuple[list[ParsedBusFrame], list[str]]:
    """Parse a bus trace with third-party readers when available, with fallback."""
    warnings: list[str] = []

    frames, third_party_warnings = _parse_with_python_can(path, dbc_path)
    warnings.extend(third_party_warnings)
    if frames:
        return frames, warnings

    fallback_frames = _parse_text_fallback(path)
    if fallback_frames:
        warnings.append(
            f"Bus parser fallback used for {path.name}; parsed {len(fallback_frames)} text rows"
        )

    return fallback_frames, warnings


def _parse_with_python_can(
    path: Path,
    dbc_path: Path | None,
) -> tuple[list[ParsedBusFrame], list[str]]:
    warnings: list[str] = []

    try:
        import can  # type: ignore[import-not-found]
    except Exception:
        warnings.append(f"python-can not available; cannot parse {path.name} with protocol reader")
        return [], warnings

    decoder, decoder_warning = _load_cantools_decoder(dbc_path)
    if decoder_warning is not None:
        warnings.append(decoder_warning)

    parsed: list[ParsedBusFrame] = []
    try:
        reader = can.LogReader(str(path))
        for line_number, message in enumerate(reader, start=1):
            timestamp = _timestamp_from_epoch(getattr(message, "timestamp", None))
            arbitration_id = _to_int(getattr(message, "arbitration_id", None))
            frame_id = f"0x{arbitration_id:X}" if arbitration_id is not None else None
            data_bytes = bytes(getattr(message, "data", b""))
            data_hex = data_bytes.hex() if data_bytes else None
            channel = _to_text(getattr(message, "channel", None))
            decoded_signals = (
                _decode_signal_values(decoder, arbitration_id, data_bytes)
                if decoder is not None
                else {}
            )

            parsed.append(
                ParsedBusFrame(
                    line_number=line_number,
                    timestamp=timestamp,
                    channel=channel,
                    frame_id=frame_id,
                    arbitration_id=arbitration_id,
                    data_hex=data_hex,
                    message=_build_bus_message(
                        frame_id=frame_id,
                        channel=channel,
                        data_hex=data_hex,
                    ),
                    decoded_signals=decoded_signals,
                )
            )
    except Exception as exc:
        warnings.append(
            f"python-can reader failed for {path.name}; using fallback text parse: {exc}"
        )
        return [], warnings

    return parsed, warnings


def _parse_text_fallback(path: Path) -> list[ParsedBusFrame]:
    parsed: list[ParsedBusFrame] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            normalized = raw_line.strip()
            if not normalized:
                continue

            frame_id = _extract_frame_id(normalized)
            arbitration_id = _to_int(frame_id, base=16) if frame_id is not None else None
            data_hex = _extract_data_hex(normalized)

            parsed.append(
                ParsedBusFrame(
                    line_number=line_number,
                    timestamp=_extract_timestamp(normalized),
                    channel=_extract_channel(normalized),
                    frame_id=frame_id,
                    arbitration_id=arbitration_id,
                    data_hex=data_hex,
                    message=normalized,
                    decoded_signals={},
                )
            )

    return parsed


def _build_bus_message(
    *,
    frame_id: str | None,
    channel: str | None,
    data_hex: str | None,
) -> str:
    frame_part = frame_id or "unknown"
    channel_part = channel or "unknown"
    data_part = data_hex or ""
    return f"CAN frame channel={channel_part} id={frame_part} data={data_part}".strip()


def _load_cantools_decoder(
    dbc_path: Path | None,
) -> tuple[Any | None, str | None]:
    if dbc_path is None:
        return None, None

    try:
        import cantools  # type: ignore[import-not-found]
    except Exception:
        return None, f"cantools not available; skipping DBC decode for {dbc_path.name}"

    try:
        database = cantools.database.load_file(str(dbc_path))
    except Exception as exc:
        return None, f"Failed to load DBC {dbc_path.name}; skipping decode: {exc}"

    return database, None


def _decode_signal_values(
    decoder: Any,
    arbitration_id: int | None,
    data_bytes: bytes,
) -> dict[str, Any]:
    if arbitration_id is None or not data_bytes:
        return {}

    try:
        decoded = decoder.decode_message(
            arbitration_id,
            data_bytes,
            decode_choices=False,
        )
    except Exception:
        return {}

    if not isinstance(decoded, dict):
        return {}

    return {str(key): _to_json_safe(value) for key, value in decoded.items()}


def _to_json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _extract_frame_id(text: str) -> str | None:
    match = _FRAME_ID_RE.search(text)
    if match is None:
        return None
    return match.group(1)


def _extract_data_hex(text: str) -> str | None:
    match = _BYTE_SEQUENCE_RE.search(text)
    if match is None:
        return None
    return match.group(1).replace(" ", "").lower()


def _extract_channel(text: str) -> str | None:
    lowered = text.lower()
    if "ch1" in lowered:
        return "1"
    if "ch2" in lowered:
        return "2"
    return None


def _timestamp_from_epoch(value: Any) -> datetime | None:
    epoch = _to_float(value)
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def _extract_timestamp(line: str) -> datetime | None:
    match = _TIMESTAMP_RE.search(line)
    if not match:
        return None

    raw = match.group(1).replace(" ", "T")
    if raw.endswith("Z"):
        raw = raw.replace("Z", "+00:00")
    elif len(raw) >= 5 and raw[-3] != ":" and (raw[-5] in {"+", "-"}):
        raw = raw[:-2] + ":" + raw[-2:]

    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _to_int(value: Any, *, base: int = 10) -> int | None:
    if value is None:
        return None

    if isinstance(value, int):
        return value

    text = _to_text(value)
    if text is None:
        return None

    try:
        return int(text, base=base)
    except ValueError:
        return None


def _to_float(value: Any) -> float | None:
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return float(value)

    text = _to_text(value)
    if text is None:
        return None

    try:
        return float(text)
    except ValueError:
        return None


def _to_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None
