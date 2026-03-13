import json
import os
import re


def analyze(sections):
    findings = []

    # --- ACL Analysis ---
    acls = sections.get("acls", [])
    acl_names = []
    for block in acls:
        match = re.match(r"(?:ip\s+)?access-list\s+(?:extended|standard)?\s*(\S+)", block)
        if match:
            acl_names.append(match.group(1))
        if "permit any any" in block or "permit ip any any" in block:
            findings.append({
                "severity": "critical",
                "category": "ACL",
                "issue": f"Overly permissive ACL rule found: permit any any",
                "detail": block.splitlines()[0],
                "recommendation": "Replace with specific permit rules following least-privilege",
            })

    if not acls:
        findings.append({
            "severity": "warning",
            "category": "ACL",
            "issue": "No access control lists configured",
            "detail": "",
            "recommendation": "Configure ACLs to restrict traffic flow",
        })

    # --- AAA Analysis ---
    aaa_config = sections.get("aaa", [])
    has_aaa = len(aaa_config) > 0
    has_aaa_auth = any("aaa authentication" in line for line in aaa_config)
    has_aaa_authz = any("aaa authorization" in line for line in aaa_config)
    has_aaa_acct = any("aaa accounting" in line for line in aaa_config)

    if not has_aaa:
        findings.append({
            "severity": "critical",
            "category": "AAA",
            "issue": "AAA is not configured",
            "detail": "",
            "recommendation": "Enable AAA with 'aaa new-model' and configure authentication, authorization, and accounting",
        })
    else:
        if not has_aaa_auth:
            findings.append({
                "severity": "critical",
                "category": "AAA",
                "issue": "AAA authentication not configured",
                "detail": "",
                "recommendation": "Configure 'aaa authentication login' methods",
            })
        if not has_aaa_authz:
            findings.append({
                "severity": "warning",
                "category": "AAA",
                "issue": "AAA authorization not configured",
                "detail": "",
                "recommendation": "Configure 'aaa authorization exec' for privilege control",
            })
        if not has_aaa_acct:
            findings.append({
                "severity": "warning",
                "category": "AAA",
                "issue": "AAA accounting not configured",
                "detail": "",
                "recommendation": "Configure 'aaa accounting' for audit trail",
            })

    # --- SSH Analysis ---
    ssh_config = sections.get("ssh", [])
    ssh_version_2 = any("version 2" in line for line in ssh_config)
    has_ssh_timeout = any("timeout" in line for line in ssh_config)

    if not ssh_version_2:
        findings.append({
            "severity": "critical",
            "category": "SSH",
            "issue": "SSH version 2 not explicitly configured",
            "detail": "",
            "recommendation": "Configure 'ip ssh version 2' to disable SSHv1",
        })
    if not has_ssh_timeout:
        findings.append({
            "severity": "warning",
            "category": "SSH",
            "issue": "No SSH timeout configured",
            "detail": "",
            "recommendation": "Set 'ip ssh time-out 60' to limit idle sessions",
        })

    # --- Line Analysis ---
    lines_config = sections.get("lines", [])
    for block in lines_config:
        if "line vty" in block:
            if "transport input ssh" not in block and "transport input all" not in block:
                if "transport input" not in block or "telnet" in block:
                    findings.append({
                        "severity": "critical",
                        "category": "Line Security",
                        "issue": "VTY lines may allow Telnet access",
                        "detail": block.splitlines()[0],
                        "recommendation": "Set 'transport input ssh' on all VTY lines",
                    })
            if "access-class" not in block:
                findings.append({
                    "severity": "warning",
                    "category": "Line Security",
                    "issue": "VTY lines missing access-class restriction",
                    "detail": block.splitlines()[0],
                    "recommendation": "Apply an ACL with 'access-class' to restrict management access",
                })

    # --- Banner Analysis ---
    banners = sections.get("banners", [])
    if not banners:
        findings.append({
            "severity": "info",
            "category": "Banner",
            "issue": "No login banner configured",
            "detail": "",
            "recommendation": "Configure a legal notice banner with 'banner login'",
        })

    # Summary
    summary = {
        "acl_count": len(acl_names),
        "aaa_enabled": has_aaa,
        "ssh_v2": ssh_version_2,
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "critical"),
        "warning": sum(1 for f in findings if f["severity"] == "warning"),
        "info": sum(1 for f in findings if f["severity"] == "info"),
    }

    return {
        "findings": findings,
        "summary": summary,
        "acl_names": acl_names,
    }


def main():
    sections = json.loads(os.environ.get("sections", "{}"))
    result = analyze(sections)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
