import argparse
import json
import os
import re
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="10.0.0.1")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--enable_secret", default="")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    username = args.username or os.environ.get("CISCO_USERNAME", "admin")
    password = args.password or os.environ.get("CISCO_PASSWORD", "")

    device = {
        "device_type": "cisco_ios",
        "host": args.host,
        "username": username,
        "password": password,
        "secret": args.enable_secret,
        "timeout": args.timeout,
    }

    conn = ConnectHandler(**device)
    if device["secret"]:
        conn.enable()

    hostname = conn.find_prompt().replace("#", "").replace(">", "").strip()
    version_output = conn.send_command("show version")
    running_config = conn.send_command("show running-config")
    conn.disconnect()

    model = ""
    os_version = ""
    uptime = ""
    serial = ""
    for line in version_output.splitlines():
        if "uptime is" in line.lower():
            uptime = line.split("uptime is")[-1].strip()
        if re.match(r"^[Cc]isco\s+\S+", line) and ("processor" in line.lower() or "bytes of" in line.lower()):
            model = line.split()[1] if len(line.split()) > 1 else ""
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
            "host": args.host,
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
