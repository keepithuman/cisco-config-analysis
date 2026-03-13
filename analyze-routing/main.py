import json
import re
import sys


def analyze(sections):
    findings = []

    # --- Dynamic Routing Analysis ---
    routing_blocks = sections.get("routing", [])
    protocols_found = []

    for block in routing_blocks:
        match = re.match(r"router\s+(\S+)\s*(\S*)", block)
        if not match:
            continue

        protocol = match.group(1).upper()
        instance = match.group(2) if match.group(2) else ""
        label = f"{protocol} {instance}".strip()
        protocols_found.append(label)

        lines = block.splitlines()
        body = "\n".join(lines[1:])

        has_passive = "passive-interface" in body
        has_auth = "authentication" in body or "key chain" in body
        has_redistribute = "redistribute" in body
        has_log_neighbor = "log-adjacency-changes" in body or "log-neighbor-changes" in body

        if not has_passive:
            findings.append({
                "severity": "warning",
                "category": "Routing",
                "protocol": label,
                "issue": f"{label}: No passive-interface configured",
                "recommendation": "Use 'passive-interface default' and selectively enable active interfaces",
            })

        if not has_auth:
            findings.append({
                "severity": "warning",
                "category": "Routing",
                "protocol": label,
                "issue": f"{label}: No routing authentication configured",
                "recommendation": f"Enable MD5 or key-chain authentication for {protocol}",
            })

        if has_redistribute:
            findings.append({
                "severity": "warning",
                "category": "Routing",
                "protocol": label,
                "issue": f"{label}: Route redistribution detected",
                "recommendation": "Verify redistribution is filtered with route-maps to prevent routing loops",
            })

        if not has_log_neighbor:
            findings.append({
                "severity": "info",
                "category": "Routing",
                "protocol": label,
                "issue": f"{label}: Neighbor change logging not enabled",
                "recommendation": f"Enable log-adjacency-changes for {protocol} troubleshooting",
            })

    # --- Static Routes Analysis ---
    static_routes = sections.get("static_routes", [])
    default_route_found = False
    for route in static_routes:
        if "0.0.0.0 0.0.0.0" in route or "0.0.0.0/0" in route:
            default_route_found = True

    if not routing_blocks and not static_routes:
        findings.append({
            "severity": "info",
            "category": "Routing",
            "protocol": "none",
            "issue": "No routing protocols or static routes configured",
            "recommendation": "Verify this device does not require routing",
        })

    summary = {
        "protocols": protocols_found,
        "static_route_count": len(static_routes),
        "has_default_route": default_route_found,
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "critical"),
        "warning": sum(1 for f in findings if f["severity"] == "warning"),
        "info": sum(1 for f in findings if f["severity"] == "info"),
    }

    return {
        "findings": findings,
        "summary": summary,
        "protocols": protocols_found,
        "static_routes": static_routes,
    }


def main():
    input_data = json.loads(sys.argv[1]) if len(sys.argv) > 1 else json.loads(sys.stdin.read())
    sections = input_data.get("sections", {})
    result = analyze(sections)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
