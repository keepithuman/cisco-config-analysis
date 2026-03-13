import argparse
import json


def analyze(sections):
    findings = []

    ntp_config = sections.get("ntp", [])
    ntp_servers = [line for line in ntp_config if "ntp server" in line]
    ntp_auth = any("ntp authenticate" in line for line in ntp_config)

    if not ntp_servers:
        findings.append({
            "severity": "critical",
            "category": "NTP",
            "issue": "No NTP servers configured",
            "recommendation": "Configure at least two NTP servers for time synchronization",
        })
    elif len(ntp_servers) < 2:
        findings.append({
            "severity": "warning",
            "category": "NTP",
            "issue": f"Only {len(ntp_servers)} NTP server configured",
            "recommendation": "Configure at least two NTP servers for redundancy",
        })

    if ntp_servers and not ntp_auth:
        findings.append({
            "severity": "warning",
            "category": "NTP",
            "issue": "NTP authentication not enabled",
            "recommendation": "Enable NTP authentication to prevent time spoofing",
        })

    logging_config = sections.get("logging", [])
    syslog_hosts = [line for line in logging_config if "logging host" in line or "logging server" in line]
    has_buffered = any("logging buffered" in line for line in logging_config)

    if not syslog_hosts:
        findings.append({
            "severity": "warning",
            "category": "Logging",
            "issue": "No remote syslog server configured",
            "recommendation": "Configure 'logging host <ip>' to send logs to a central syslog server",
        })

    if not has_buffered:
        findings.append({
            "severity": "info",
            "category": "Logging",
            "issue": "Local log buffering not configured",
            "recommendation": "Configure 'logging buffered <size>' for local log retention",
        })

    snmp_config = sections.get("snmp", [])
    has_snmp = len(snmp_config) > 0
    snmp_v3 = any("snmp-server group" in line or "snmp-server user" in line for line in snmp_config)
    community_strings = [line for line in snmp_config if "snmp-server community" in line]

    if has_snmp and not snmp_v3 and community_strings:
        findings.append({
            "severity": "warning",
            "category": "SNMP",
            "issue": "Using SNMPv2c community strings instead of SNMPv3",
            "recommendation": "Migrate to SNMPv3 with authentication and encryption",
        })

    for comm in community_strings:
        if "RW" in comm.upper() or " rw" in comm.lower():
            findings.append({
                "severity": "critical",
                "category": "SNMP",
                "issue": "SNMP read-write community string found",
                "recommendation": "Remove RW community strings; use SNMPv3 for write access",
            })

    default_communities = ["public", "private"]
    for comm in community_strings:
        for default in default_communities:
            if default in comm.lower():
                findings.append({
                    "severity": "critical",
                    "category": "SNMP",
                    "issue": f"Default SNMP community string '{default}' in use",
                    "recommendation": f"Remove default community '{default}' immediately",
                })

    if not has_snmp:
        findings.append({
            "severity": "info",
            "category": "SNMP",
            "issue": "SNMP is not configured",
            "recommendation": "Configure SNMPv3 if network monitoring is required",
        })

    dns_config = sections.get("dns", [])
    dns_servers = [line for line in dns_config if "name-server" in line]

    if not dns_servers:
        findings.append({
            "severity": "info",
            "category": "DNS",
            "issue": "No DNS name-servers configured",
            "recommendation": "Configure DNS servers if name resolution is needed",
        })

    summary = {
        "ntp_servers": len(ntp_servers),
        "ntp_auth": ntp_auth,
        "syslog_hosts": len(syslog_hosts),
        "snmp_version": "v3" if snmp_v3 else ("v2c" if community_strings else "none"),
        "dns_servers": len(dns_servers),
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "critical"),
        "warning": sum(1 for f in findings if f["severity"] == "warning"),
        "info": sum(1 for f in findings if f["severity"] == "info"),
    }

    return {
        "findings": findings,
        "summary": summary,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sections", required=True)
    args = parser.parse_args()

    sections = json.loads(args.sections)
    result = analyze(sections)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
