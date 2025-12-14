"""
Automated Linux Firewall Health & Compliance Checker
Checks basic firewall status and flags potential security issues.

Author: Thomas David Stewart
Course: CYB 333 Security Automation
"""

import argparse
import datetime as dt
import subprocess
from pathlib import Path


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    """Run a command safely and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"


def detect_firewall_tool() -> str:
    """Detect whether ufw or iptables is available."""
    for tool in ("ufw", "iptables"):
        code, _, _ = run_cmd([tool, "--version"])
        if code == 0:
            return tool
    return "none"


def get_ufw_status() -> dict:
    """Collect UFW status and rules."""
    code, out, err = run_cmd(["ufw", "status", "verbose"])
    return {"tool": "ufw", "ok": code == 0, "output": out, "error": err}


def get_iptables_rules() -> dict:
    """Collect iptables rules (filter table)."""
    code, out, err = run_cmd(["iptables", "-S"])
    return {"tool": "iptables", "ok": code == 0, "output": out, "error": err}


def simple_findings(raw: str) -> list[str]:
    """
    Very basic checks:
    - Flag if it looks like firewall is inactive/disabled
    - Flag if common risky ports appear open/allowed (heuristic based on text)
    """
    findings = []

    lower = raw.lower()

    if "inactive" in lower or "disabled" in lower:
        findings.append("Firewall appears inactive/disabled.")

    # Heuristic checks for common exposed services (not perfect, but useful as a baseline)
    risky_ports = {
        "22": "SSH (22)",
        "23": "Telnet (23)",
        "3389": "RDP (3389)",
        "5900": "VNC (5900)",
        "3306": "MySQL (3306)",
        "5432": "PostgreSQL (5432)",
    }

    for port, label in risky_ports.items():
        # UFW often shows "22/tcp ALLOW", iptables might show "--dport 22"
        if f"{port}/tcp" in lower and "allow" in lower:
            findings.append(f"Rule appears to allow {label}. Review if this should be exposed.")
        if f"--dport {port}" in lower:
            findings.append(f"iptables rules reference {label}. Confirm exposure is intended.")

    return findings


def write_report(path: Path, tool: str, raw_output: str, findings: list[str]) -> None:
    """Write a timestamped report to a file."""
    ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append(f"Firewall Health & Compliance Report")
    lines.append(f"Timestamp: {ts}")
    lines.append(f"Detected Tool: {tool}")
    lines.append("")
    lines.append("=== Findings ===")
    if findings:
        for f in findings:
            lines.append(f"- {f}")
    else:
        lines.append("- No obvious issues detected by basic checks.")
    lines.append("")
    lines.append("=== Raw Output ===")
    lines.append(raw_output)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Linux Firewall Health & Compliance Checker")
    parser.add_argument("--output", default="reports/firewall_report.txt", help="Report output path")
    args = parser.parse_args()

    tool = detect_firewall_tool()

    if tool == "none":
        msg = "No supported firewall tools detected (ufw/iptables). This is expected on Windows. Run in Linux/WSL/VM for real firewall checks."
        report_path = Path(args.output)
        write_report(report_path, tool, msg, [msg])
        print(f"[OK] Report saved to: {report_path}")
        print(msg)
        return 0


    data = get_ufw_status() if tool == "ufw" else get_iptables_rules()

    if not data["ok"]:
        print(f"Failed to collect {tool} data: {data['error']}")
        return 2

    findings = simple_findings(data["output"])
    report_path = Path(args.output)
    write_report(report_path, tool, data["output"], findings)

    print(f"[OK] Report saved to: {report_path}")
    if findings:
        print("Findings:")
        for f in findings:
            print(f" - {f}")
    else:
        print("No obvious issues found (basic checks).")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
