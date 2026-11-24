"""Check captured NAS messages against an expected call flow."""
from dataclasses import dataclass, field

from .flows import FLOWS
from .parser import load_messages


@dataclass
class Result:
    flow: str
    passed: bool
    found: list = field(default_factory=list)        # (step name, frame)
    missing: list = field(default_factory=list)      # step names never seen
    out_of_order: list = field(default_factory=list)
    rejected: list = field(default_factory=list)     # (name, frame, cause)
    unverified: list = field(default_factory=list)   # steps hidden by ciphering
    ciphered_frames: list = field(default_factory=list)


def analyze(messages, flow_name):
    flow = FLOWS[flow_name]
    names = flow["names"]
    res = Result(flow=flow_name, passed=True)

    causes = flow.get("causes", {})
    for m in messages:
        if m["code"] == flow["reject_code"]:
            try:
                c = int(str(m["cause"]), 0)
            except (TypeError, ValueError):
                c = None
            text = f"{m['cause']} - {causes[c]}" if c in causes else m["cause"]
            res.rejected.append((names[m["code"]], m["frame"], text))

    last_frame_idx = -1
    for code, required in flow["steps"]:
        idx = next((i for i, m in enumerate(messages) if m["code"] == code), None)
        if idx is None:
            if required:
                res.missing.append(names[code])
            continue
        res.found.append((names[code], messages[idx]["frame"]))
        if idx < last_frame_idx:
            res.out_of_order.append(names[code])
        last_frame_idx = max(last_frame_idx, idx)

    # Steps after Security Mode Command may be ciphered: report them as unverifiable
    sec_idx = next((i for i, m in enumerate(messages) if m["code"] == flow.get("security_step")), None)
    if sec_idx is not None:
        later = [m for m in messages[sec_idx + 1:] if m.get("ciphered")]
        if later and not res.rejected:
            res.ciphered_frames = [m["frame"] for m in later]
            sec_pos = [c for c, _ in flow["steps"]].index(flow["security_step"])
            after = {names[c] for c, _ in flow["steps"][sec_pos + 1:]}
            res.unverified = [n for n in res.missing if n in after]
            res.missing = [n for n in res.missing if n not in after]

    res.passed = not (res.missing or res.out_of_order or res.rejected)
    return res


def analyze_file(path, flow_name):
    flow = FLOWS[flow_name]
    msgs = load_messages(path, flow["field"], flow["cause_field"], flow.get("layer"))
    return analyze(msgs, flow_name)


def format_report(res):
    verdict = "FAIL" if not res.passed else ("PASS (partial: ciphered messages not verifiable)" if res.unverified else "PASS")
    lines = [f"Flow: {res.flow}", f"Result: {verdict}", ""]
    for name, frame in res.found:
        lines.append(f"  [ok]      {name} (frame {frame})")
    for name in res.unverified:
        lines.append(f"  [CIPHERED] {name} - cannot verify without NAS keys")
    for name in res.missing:
        lines.append(f"  [MISSING] {name}")
    for name in res.out_of_order:
        lines.append(f"  [ORDER]   {name} arrived before an earlier step")
    for name, frame, cause in res.rejected:
        lines.append(f"  [REJECT]  {name} (frame {frame}), cause: {cause}")
    return "\n".join(lines)
