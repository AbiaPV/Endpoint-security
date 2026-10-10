SUSPICIOUS_TOOLS = {"mimikatz.exe", "nc.exe", "ncat.exe", "psexec.exe", "procdump.exe"}
COMMAND_SHELLS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"}
SUSPICIOUS_KEYWORDS = [
    "-enc", "-encodedcommand", "downloadstring", "invoke-expression",
    "iex ", "bypass", "hidden", "frombase64string",
]


def _make_alert(rule, severity, description):
    return {
        "rule": rule,
        "severity": severity,
        "risk": severity,
        "risk_level": severity,
        "description": description,
        "message": description,
        "reason": description,
    }


def check_rules(event):
    """Return a list of alerts for one process event."""
    alerts = []

    name = str(event.get("process_name") or event.get("name") or event.get("process") or "").lower()
    cmd = str(event.get("command_line") or event.get("cmdline") or event.get("command") or "").lower()

    if name in SUSPICIOUS_TOOLS:
        alerts.append(_make_alert(
            "Known attack tool", "high", f"{name} is a known attack tool"))

    if name in COMMAND_SHELLS:
        alerts.append(_make_alert(
            "Command shell started", "medium", f"{name} can be used to run commands"))

    for word in SUSPICIOUS_KEYWORDS:
        if word in cmd:
            alerts.append(_make_alert(
                "Suspicious command line", "high", f"Command line contains '{word.strip()}'"))
            break

    return alerts