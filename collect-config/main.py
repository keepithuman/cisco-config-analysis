import json
import re
import sys
from netmiko import ConnectHandler


SECTION_PATTERNS = {
    "interfaces": r"^interface\s+\S+.*?(?=^!\s*$)",
    "routing": r"^router\s+\S+.*?(?=^!\s*$)",
    "acls": r"^(?:ip\s+)?access-list\s+.*?(?=^!\s*$)",
    "aaa": r"^aaa\s+.*?(?=^!\s*$)",
    "lines": r"^line\s+\S+.*?(?=^!\s*$)",
    "ntp": r"^ntp\s+.*$",
    "logging": r"^logging\s+.*$",
    "snmp": r"^snmp-server\s+.*$",
    "dns": r"^ip\s+(?:name-server|domain).*$",
    "ssh": r"^ip\s+ssh\s+.*$",
    "static_routes": r"^ip\s+route\s+.*$",
    "banners": r"^banner\s+\S+.*?(?=^!\s*$)",
}


def parse_sections(config_text):
    sections = {}
    for name, pattern in SECTION_PATTERNS.items():
        flags = re.MULTILINE | re.DOTALL
        matches = re.findall(pattern, config_text, flags)
        if matches:
            sections[name] = [m.strip() for m in matches]
        else:
            sections[name] = []
    return sections


def main():
    input_data = json.loads(sys.argv[1]) if len(sys.argv) > 1 else json.loads(sys.stdin.read())

    device = {
        "device_type": "cisco_ios",
        "host": input_data["host"],
        "username": input_data["username"],
        "password": input_data["password"],
        "secret": input_data.get("enable_secret", ""),
        "timeout": input_data.get("timeout", 30),
    }

    conn = ConnectHandler(**device)
    if device["secret"]:
        conn.enable()

    hostname = conn.find_prompt().replace("#", "").replace(">", "").strip()
    version_output = conn.send_command("show version")
    running_config = conn.send_command("show running-config")
    conn.disconnect()

    # Extract basic device info from show version
    model = ""
    os_version = ""
    uptime = ""
    serial = ""
    for line in version_output.splitlines():
        if "uptime is" in line.lower():
            uptime = line.split("uptime is")[-1].strip()
        if re.match(r"^[Cc]isco\s+\S+", line) and ("processor" in line.lower() or "bytes of" in line.lower()):
            model = line.split()[1] if len(line.split()) > 1 else ""
        if "system image file" in line.lower() or "system returned to rom" in line.lower():
            pass
        ver_match = re.search(r"Version\s+([\S]+)", line)
        if ver_match:
            os_version = ver_match.group(1).rstrip(",")
        ser_match = re.search(r"[Bb]oard ID\s+(\S+)", line)
        if ser_match:
            serial = ser_match.group(1)

    sections = parse_sections(running_config)

    result = {
        "device_info": {
            "hostname": hostname,
            "host": input_data["host"],
            "model": model,
            "os_version": os_version,
            "uptime": uptime,
            "serial": serial,
        },
        "sections": sections,
        "raw_config": running_config,
    }

    print(json.dumps(result))


if __name__ == "__main__":
    main()
