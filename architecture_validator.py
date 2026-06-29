import json
from datetime import datetime

# ============================================================
# SECURE CLOUD NETWORKING ARCHITECTURE VALIDATOR
# Validates the architecture design against security
# best practices and generates a client-ready HTML report
# Author: Fatehah Burhannudin
# ============================================================

# Architecture definition — mirrors the Bicep template
ARCHITECTURE = {
    "name": "Secure Cloud Networking Architecture",
    "platform": "Microsoft Azure",
    "iac_tool": "Bicep (Azure-native IaC)",
    "environment": "Production",
    "region": "Southeast Asia (Malaysia)",
    "vnet": {
        "address_space": "10.0.0.0/16",
        "ddos_protection": True,
        "subnets": [
            {
                "name": "subnet-web",
                "prefix": "10.0.1.0/24",
                "tier": "Web Tier",
                "nsg": "nsg-web-production",
                "allowed_inbound": ["HTTPS:443", "HTTP:80"],
                "allowed_from": "Internet",
                "description": "Public-facing tier — hosts web servers and load balancers"
            },
            {
                "name": "subnet-app",
                "prefix": "10.0.2.0/24",
                "tier": "Application Tier",
                "nsg": "nsg-app-production",
                "allowed_inbound": ["APP:8080"],
                "allowed_from": "10.0.1.0/24 (Web Subnet only)",
                "description": "Business logic tier — no direct internet access"
            },
            {
                "name": "subnet-data",
                "prefix": "10.0.3.0/24",
                "tier": "Data Tier",
                "nsg": "nsg-data-production",
                "allowed_inbound": ["SQL:1433"],
                "allowed_from": "10.0.2.0/24 (App Subnet only)",
                "description": "Database tier — most restricted, no internet access"
            },
            {
                "name": "subnet-mgmt",
                "prefix": "10.0.4.0/24",
                "tier": "Management Tier",
                "nsg": "nsg-mgmt-production",
                "allowed_inbound": ["RDP:3389", "SSH:22"],
                "allowed_from": "Authorised IPs only",
                "description": "Admin access tier — Azure Bastion for secure remote access"
            }
        ]
    },
    "security_controls": [
        {
            "control": "Network Security Groups (NSG)",
            "status": "IMPLEMENTED",
            "description": "Subnet-level firewall rules enforcing least-privilege access",
            "standard": "Azure Security Benchmark NS-1"
        },
        {
            "control": "DDoS Protection Standard",
            "status": "IMPLEMENTED",
            "description": "Always-on traffic monitoring and automatic attack mitigation",
            "standard": "Azure Security Benchmark NS-5"
        },
        {
            "control": "Defence in Depth (3-tier)",
            "status": "IMPLEMENTED",
            "description": "Web, app, and data tiers isolated — traffic must traverse layers sequentially",
            "standard": "Zero Trust Architecture Principle"
        },
        {
            "control": "Private Endpoint Policies",
            "status": "IMPLEMENTED",
            "description": "Private endpoints enabled on all subnets for PaaS service access",
            "standard": "Azure Security Benchmark NS-3"
        },
        {
            "control": "Role-Based Access Control (RBAC)",
            "status": "DESIGNED",
            "description": "Least-privilege RBAC roles scoped per subnet and resource group",
            "standard": "Azure Security Benchmark PA-7"
        },
        {
            "control": "Infrastructure as Code (Bicep)",
            "status": "IMPLEMENTED",
            "description": "All infrastructure defined in version-controlled Bicep templates",
            "standard": "Azure Security Benchmark DS-6"
        },
        {
            "control": "Azure Monitor & Log Analytics",
            "status": "DESIGNED",
            "description": "NSG flow logs, VNet diagnostics, and security alerts configured",
            "standard": "Azure Security Benchmark LT-3"
        },
        {
            "control": "Microsoft Defender for Cloud",
            "status": "DESIGNED",
            "description": "Continuous security posture assessment and threat detection",
            "standard": "Azure Security Benchmark LT-1"
        }
    ]
}

# Security validation checks
def validate_architecture(arch):
    checks = []

    # Check DDoS protection
    ddos = arch["vnet"]["ddos_protection"]
    checks.append({
        "check": "DDoS Protection Enabled",
        "result": "PASS" if ddos else "FAIL",
        "detail": "DDoS Protection Standard enabled on VNet" if ddos else "DDoS Protection not enabled — HIGH RISK"
    })

    # Check all subnets have NSGs
    subnets_with_nsg = all(s.get("nsg") for s in arch["vnet"]["subnets"])
    checks.append({
        "check": "All Subnets Have NSGs",
        "result": "PASS" if subnets_with_nsg else "FAIL",
        "detail": "All subnets protected by Network Security Groups" if subnets_with_nsg else "Some subnets missing NSGs"
    })

    # Check data tier not exposed to internet
    data_subnet = next(s for s in arch["vnet"]["subnets"] if s["tier"] == "Data Tier")
    data_protected = "Internet" not in data_subnet["allowed_from"]
    checks.append({
        "check": "Data Tier Internet Isolation",
        "result": "PASS" if data_protected else "FAIL",
        "detail": "Data tier has no direct internet access — only accessible from app tier" if data_protected else "Data tier exposed to internet — CRITICAL RISK"
    })

    # Check app tier not exposed to internet
    app_subnet = next(s for s in arch["vnet"]["subnets"] if s["tier"] == "Application Tier")
    app_protected = "Internet" not in app_subnet["allowed_from"]
    checks.append({
        "check": "App Tier Internet Isolation",
        "result": "PASS" if app_protected else "FAIL",
        "detail": "App tier not directly accessible from internet — only from web tier" if app_protected else "App tier exposed to internet — HIGH RISK"
    })

    # Check IaC is used
    iac_used = bool(arch.get("iac_tool"))
    checks.append({
        "check": "Infrastructure as Code",
        "result": "PASS" if iac_used else "WARN",
        "detail": f"IaC implemented using {arch['iac_tool']}" if iac_used else "No IaC tool detected — manual deployment risk"
    })

    # Check RBAC is designed
    rbac = next((c for c in arch["security_controls"] if "RBAC" in c["control"]), None)
    checks.append({
        "check": "RBAC Configuration",
        "result": "PASS" if rbac else "WARN",
        "detail": rbac["description"] if rbac else "RBAC not configured"
    })

    # Check monitoring is designed
    monitoring = next((c for c in arch["security_controls"] if "Monitor" in c["control"]), None)
    checks.append({
        "check": "Monitoring & Logging",
        "result": "PASS" if monitoring else "WARN",
        "detail": monitoring["description"] if monitoring else "Monitoring not configured"
    })

    return checks

def get_result_color(result):
    return {"PASS": "#107c10", "FAIL": "#d83b01", "WARN": "#ff8c00"}.get(result, "#666")

def get_status_color(status):
    return {"IMPLEMENTED": "#107c10", "DESIGNED": "#0078d4", "PLANNED": "#ff8c00"}.get(status, "#666")

# Run validation
print("Secure Cloud Networking Architecture Validator")
print("="*55)

checks = validate_architecture(ARCHITECTURE)
passed = sum(1 for c in checks if c["result"] == "PASS")
failed = sum(1 for c in checks if c["result"] == "FAIL")
warned = sum(1 for c in checks if c["result"] == "WARN")

for c in checks:
    print(f"[{c['result']}] {c['check']}")

print(f"\nSummary: {passed} Passed | {failed} Failed | {warned} Warnings")

# Generate HTML report
now = datetime.now()
timestamp = now.strftime("%Y-%m-%d %H:%M")
report_date = now.strftime("%B %d, %Y")

html = f"""<!DOCTYPE html>
<html>
<head>
<title>Secure Cloud Network Architecture Report</title>
<style>
body{{font-family:Arial;margin:auto;max-width:1100px;padding:40px;color:#333}}
h1{{color:#1a1a2e;border-bottom:3px solid #1a1a2e;padding-bottom:10px}}
h2{{color:#1a1a2e;margin-top:30px}}
h3{{color:#333;margin-top:20px}}
.meta{{color:#666;font-size:13px;line-height:1.8;margin-bottom:20px}}
.info{{background:#f0f8ff;border-left:4px solid #0078d4;padding:15px;margin:15px 0;border-radius:0 5px 5px 0}}
table{{border-collapse:collapse;width:100%;margin:15px 0;font-size:13px}}
th{{background:#1a1a2e;color:white;padding:10px;text-align:left}}
td{{padding:8px 10px;border-bottom:1px solid #eee}}
tr:nth-child(even){{background:#f9f9f9}}
.PASS{{color:#107c10;font-weight:bold}}
.FAIL{{color:#d83b01;font-weight:bold}}
.WARN{{color:#ff8c00;font-weight:bold}}
.badge{{display:inline-block;padding:3px 10px;border-radius:12px;color:white;font-size:12px;font-weight:bold}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin:20px 0}}
.card{{padding:15px;border-radius:8px;text-align:center;color:white}}
.card h3{{margin:0;font-size:32px}}
.card p{{margin:5px 0 0;font-size:13px}}
.arch-box{{background:#f8f9fa;border:1px solid #ddd;border-radius:8px;padding:15px;margin:10px 0;font-family:monospace;font-size:12px;line-height:1.6}}
.footer{{margin-top:40px;font-size:12px;color:#666;border-top:1px solid #ddd;padding-top:15px}}
</style>
</head>
<body>
<h1>Secure Cloud Networking Architecture Report</h1>
<div class="meta">
<strong>Architecture:</strong> {ARCHITECTURE['name']}<br>
<strong>Platform:</strong> {ARCHITECTURE['platform']} &nbsp;|&nbsp;
<strong>IaC Tool:</strong> {ARCHITECTURE['iac_tool']} &nbsp;|&nbsp;
<strong>Region:</strong> {ARCHITECTURE['region']}<br>
<strong>Generated:</strong> {report_date} at {timestamp} &nbsp;|&nbsp;
<strong>Prepared by:</strong> Fatehah Burhannudin
</div>

<div class="info">
<strong>Architecture Overview:</strong> A secure three-tier Azure network architecture implementing defence-in-depth, least-privilege access, and Zero Trust principles. Deployed via Bicep IaC ensuring consistency and repeatability. All components follow the Azure Security Benchmark and Microsoft Well-Architected Framework security pillar.
</div>

<h2>Architecture Diagram</h2>
<div class="arch-box">
Internet
    |
    v
[Azure DDoS Protection Standard]
    |
    v
+------------------------------------------+
|         VNet: 10.0.0.0/16               |
|                                          |
|  [subnet-web: 10.0.1.0/24]              |
|   NSG: Allow HTTPS:443, HTTP:80          |
|   from Internet only                     |
|         |                                |
|         v (port 8080 only)              |
|  [subnet-app: 10.0.2.0/24]              |
|   NSG: Allow from Web subnet only        |
|         |                                |
|         v (port 1433 only)              |
|  [subnet-data: 10.0.3.0/24]             |
|   NSG: Allow from App subnet only        |
|                                          |
|  [subnet-mgmt: 10.0.4.0/24]             |
|   NSG: Allow from authorised IPs only    |
+------------------------------------------+
</div>

<h2>Security Validation Results</h2>
<div class="grid">
<div class="card" style="background:#107c10"><h3>{passed}</h3><p>Checks Passed</p></div>
<div class="card" style="background:#d83b01"><h3>{failed}</h3><p>Checks Failed</p></div>
<div class="card" style="background:#ff8c00"><h3>{warned}</h3><p>Warnings</p></div>
</div>

<table>
<tr><th>Security Check</th><th>Result</th><th>Detail</th></tr>"""

for c in checks:
    html += f"""<tr>
<td>{c['check']}</td>
<td class="{c['result']}">{c['result']}</td>
<td>{c['detail']}</td>
</tr>"""

html += """</table>
<h2>Network Architecture — Subnet Design</h2>
<table>
<tr><th>Subnet</th><th>Address</th><th>Tier</th><th>Allowed Inbound</th><th>Allowed From</th><th>Description</th></tr>"""

for s in ARCHITECTURE["vnet"]["subnets"]:
    ports = ", ".join(s["allowed_inbound"])
    html += f"""<tr>
<td><strong>{s['name']}</strong></td>
<td>{s['prefix']}</td>
<td>{s['tier']}</td>
<td>{ports}</td>
<td>{s['allowed_from']}</td>
<td>{s['description']}</td>
</tr>"""

html += """</table>
<h2>Security Controls Implementation Status</h2>
<table>
<tr><th>Security Control</th><th>Status</th><th>Description</th><th>Standard Reference</th></tr>"""

for c in ARCHITECTURE["security_controls"]:
    color = get_status_color(c["status"])
    html += f"""<tr>
<td><strong>{c['control']}</strong></td>
<td><span class="badge" style="background:{color}">{c['status']}</span></td>
<td>{c['description']}</td>
<td>{c['standard']}</td>
</tr>"""

html += f"""</table>

<h2>IaC Deployment Reference</h2>
<div class="info">
<strong>Template:</strong> main.bicep — Azure Resource Manager Bicep template<br>
<strong>Parameters:</strong> parameters.json — Environment-specific configuration<br>
<strong>Deploy command:</strong><br>
<code style="background:#1a1a2e;color:#fff;padding:8px 12px;border-radius:4px;display:inline-block;margin-top:8px">
az deployment group create --resource-group rg-secure-network --template-file main.bicep --parameters @parameters.json
</code>
</div>

<h2>Design Principles Applied</h2>
<table>
<tr><th>Principle</th><th>Implementation</th></tr>
<tr><td>Defence in Depth</td><td>Three-tier isolation — web, app, data. Traffic must traverse layers sequentially</td></tr>
<tr><td>Least Privilege</td><td>Each NSG only allows minimum required ports from minimum required sources</td></tr>
<tr><td>Zero Trust</td><td>No implicit trust between subnets — all cross-tier traffic explicitly controlled by NSG rules</td></tr>
<tr><td>Infrastructure as Code</td><td>Entire architecture defined in Bicep — version controlled, repeatable, consistent</td></tr>
<tr><td>DDoS Resilience</td><td>Azure DDoS Protection Standard enabled at VNet level — automatic mitigation</td></tr>
<tr><td>Parameterisation</td><td>Environment name and IP ranges parameterised — same template deploys to dev/staging/prod</td></tr>
</table>

<h2>Azure Well-Architected Framework Alignment</h2>
<table>
<tr><th>Pillar</th><th>How This Architecture Aligns</th></tr>
<tr><td>Security</td><td>NSGs, DDoS protection, private endpoints, least-privilege access, RBAC</td></tr>
<tr><td>Reliability</td><td>DDoS protection prevents availability attacks; subnet isolation limits blast radius of failures</td></tr>
<tr><td>Operational Excellence</td><td>IaC deployment via Bicep; Azure Monitor for observability; consistent tagging</td></tr>
<tr><td>Performance Efficiency</td><td>Subnet separation allows independent scaling of each tier</td></tr>
<tr><td>Cost Optimisation</td><td>Parameterised deployment enables right-sizing per environment</td></tr>
</table>

<div class="footer">
<p><strong>Fatehah Burhannudin</strong> | fatehahdean@gmail.com | linkedin.com/in/fatehahburhannudin</p>
<p>Architecture designed and validated using Azure security best practices, Azure Security Benchmark, and Microsoft Well-Architected Framework guidelines.</p>
<p>Generated: {timestamp}</p>
</div>
</body></html>"""

filename = f"architecture_report_{now.strftime('%Y%m%d_%H%M')}.html"
with open(filename, "w") as f:
    f.write(html)

print(f"\nReport saved: {filename}")
print("Open the HTML file in your browser to view the full report.")