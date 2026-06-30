# Secure Cloud Networking Architecture

A secure three-tier Azure network architecture implementing defence-in-depth, least-privilege access, and Zero Trust principles. Deployed via Bicep IaC ensuring consistency and repeatability.

## What's in this repo

- `main.bicep` — Azure Bicep IaC template defining the full network architecture
- `parameters.json` — Environment-specific configuration (region, IP ranges, environment name)
- `architecture_validator.py` — Python script that validates the architecture against security best practices and generates an HTML report

## Security Controls

| Control | Status |
|---------|--------|
| Network Security Groups (NSG) | Implemented |
| DDoS Protection Standard | Implemented |
| Defence in Depth (3-tier) | Implemented |
| Private Endpoint Policies | Implemented |
| RBAC — Least Privilege | Designed |
| Azure Monitor & Log Analytics | Designed |
| Microsoft Defender for Cloud | Designed |
| Infrastructure as Code (Bicep) | Implemented |

## Security Validation Results

7 automated security checks — **7 Passed | 0 Failed | 0 Warnings**

<img width="810" height="215" alt="Screenshot 2026-07-01 at 1 08 27 AM" src="https://github.com/user-attachments/assets/46169ea4-a342-487f-b5e3-7d7cca996c3d" />


## How to Deploy

```bash
az login
az group create --name rg-secure-network --location southeastasia
az deployment group create --resource-group rg-secure-network --template-file main.bicep --parameters @parameters.json
```

## Run the Validator

```bash
python3 architecture_validator.py
```

## Design Principles

- **Defence in Depth** — three-tier isolation, traffic traverses layers sequentially
- **Least Privilege** — each NSG allows minimum required ports from minimum required sources
- **Zero Trust** — no implicit trust between subnets
- **Infrastructure as Code** — entire architecture version-controlled in Bicep
- **DDoS Resilience** — Azure DDoS Protection Standard at VNet level

## Technologies Used

- Microsoft Azure (VNet, NSG, DDoS Protection)
- Bicep (Azure-native IaC)
- Python 3.13
- Azure CLI
