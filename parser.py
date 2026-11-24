"""Read a tshark JSON export (`tshark -r x.pcap -T json`) and pull out NAS messages."""
import json


def _walk(node, key):
    """Yield every value stored under `key` anywhere in a nested dict/list."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                yield from (v if isinstance(v, list) else [v])
            else:
                yield from _walk(v, key)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item, key)


def _to_int(value):
    s = str(value).strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def _num(value, cast):
    """Convert to a number, or return None if the value is not numeric."""
    try:
        return cast(value)
    except (TypeError, ValueError):
        return None


def load_messages(path, field, cause_field=None, layer=None):
    """Return a list of dicts: frame, time, code, cause (in capture order)."""
    with open(path, encoding="utf-8") as f:
        packets = json.load(f)
    out = []
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        frame = next(_walk(layers.get("frame", {}), "frame.number"), None)
        ts = next(_walk(layers.get("frame", {}), "frame.time_epoch"), None)
        cause = next(_walk(layers, cause_field), None) if cause_field else None
        raws = list(_walk(layers, field))
        if not raws and layer and any(True for _ in _walk(layers, layer)):
            # NAS present but message type unreadable -> ciphered by the security context
            out.append({"frame": _num(frame, int), "time": ts, "code": None,
                        "cause": None, "ciphered": True})
        for raw in raws:
            out.append({"frame": _num(frame, int),
                        "time": ts,
                        "code": _to_int(raw),
                        "cause": cause})
    return out
