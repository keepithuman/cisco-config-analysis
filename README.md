# cisco-config-analysis

Multi-service IAG5 repo for Cisco IOS configuration analysis. Collects running config sections, analyzes interfaces, security, routing, and network services, then renders findings via a Jinja2 HTML report template.

## Services

| Service | Description |
|---------|------------|
| `collect-config` | Connects to device via Netmiko, pulls running config, parses into sections |
| `analyze-interfaces` | Evaluates interface status, descriptions, IPs |
| `analyze-security` | Checks ACLs, AAA, SSH, VTY line security, banners |
| `analyze-routing` | Reviews routing protocols, static routes, authentication |
| `analyze-services` | Audits NTP, logging, SNMP, DNS configuration |

## Workflow

```
collect-config → [ analyze-interfaces | analyze-security | analyze-routing | analyze-services ] → J2 HTML report
```

## Template

`templates/report.html.j2` — inline-styled HTML report for rendering in Itential Platform.
