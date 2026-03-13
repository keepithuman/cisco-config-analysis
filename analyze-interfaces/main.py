import json
import os
import re


def analyze(interface_blocks):
    findings = []
    interfaces = []

    for block in interface_blocks:
        lines = block.strip().splitlines()
        if not lines:
            continue

        name_match = re.match(r"interface\s+(\S+)", lines[0])
        if not name_match:
            continue

        iface_name = name_match.group(1)
        body = "\n".join(lines[1:])

        iface = {
            "name": iface_name,
            "shutdown": "shutdown" in body and "no shutdown" not in body,
            "has_description": "description " in body,
            "has_ip": "ip address " in body and "no ip address" not in body,
            "description": "",
            "ip_address": "",
            "duplex": "",
            "speed": "",
        }

        for line in lines[1:]:
            line = line.strip()
            if line.startswith("description "):
                iface["description"] = line.replace("description ", "", 1)
            if line.startswith("ip address ") and "no ip address" not in line:
                iface["ip_address"] = line.replace("ip address ", "", 1)
            if line.startswith("duplex "):
                iface["duplex"] = line.replace("duplex ", "", 1)
            if line.startswith("speed "):
                iface["speed"] = line.replace("speed ", "", 1)

        interfaces.append(iface)

        # Findings
        if not iface["has_description"] and not iface["shutdown"]:
            findings.append({
                "severity": "warning",
                "interface": iface_name,
                "issue": "Active interface missing description",
                "recommendation": f"Add a description to {iface_name} for operational clarity",
            })

        if iface["shutdown"]:
            findings.append({
                "severity": "info",
                "interface": iface_name,
                "issue": "Interface is shutdown",
                "recommendation": "Verify this port is intentionally disabled",
            })

    summary = {
        "total": len(interfaces),
        "active": sum(1 for i in interfaces if not i["shutdown"]),
        "shutdown": sum(1 for i in interfaces if i["shutdown"]),
        "with_ip": sum(1 for i in interfaces if i["has_ip"]),
        "missing_description": sum(1 for i in interfaces if not i["has_description"] and not i["shutdown"]),
    }

    return {
        "interfaces": interfaces,
        "findings": findings,
        "summary": summary,
    }


def main():
    sections = json.loads(os.environ.get("sections", "{}"))
    interface_blocks = sections.get("interfaces", [])
    result = analyze(interface_blocks)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
