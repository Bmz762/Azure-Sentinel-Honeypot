![Azure](https://img.shields.io/badge/azure-%230072C6.svg?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-%230078D4.svg?style=for-the-badge&logo=microsoft&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-%235391FE.svg?style=for-the-badge&logo=powershell&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Kusto%20Query%20Language-orange?style=for-the-badge)
# Azure-Sentinel-Honeypot
<img width="1731" height="738" alt="honey_pot_HeatMap_v2" src="https://github.com/user-attachments/assets/0d56f0ee-8df5-4dd9-92c4-7b7e44d91442" />

Quick Overview
This project involved the deployment of a Windows 10 Virtual Machine as a "honeypot" on Microsoft Azure. The goal was to attract, monitor, and visualize real-time RDP (Remote Desktop Protocol) brute-force attacks from across the globe. By utilizing Microsoft Sentinel (SIEM) and a custom PowerShell script, I transformed raw security logs into a geographical heatmap to analyze attacker origins and patterns.

Technologies & Skills Used:
Cloud: Microsoft Azure (Virtual Machines, Network Security Groups)
SIEM: Microsoft Sentinel (SIEM), Log Analytics Workspaces (LAW)
Languages: Kusto Query Language (KQL), PowerShell
APIs: IPGeolocation.io (Geo-Data Enrichment)
Security Concepts: Threat Detection, Log Analysis, Brute-Force Monitoring

Total Number of Attacks : 2288
Top 3 Attacking Countries: Kyrgyzstan - 212.42.122.66, China - 120.211.171.91, and France - 194.3.181.177
# Project Implementation Steps
1. Environment Setup (Azure VM)
Provisioning: Created a Windows 10 Virtual Machine in Azure.

Networking: Configured the Network Security Group (NSG) with an Inbound Security Rule to allow Any traffic on Port 3389 (RDP).

Vulnerability: This made the VM "discoverable" to scanners and botnets within minutes.

2. Log Analytics & Sentinel Configuration
Workspace: Created a Log Analytics Workspace (LAW) to act as the central repository for security logs.

SIEM Activation: Enabled Microsoft Sentinel on top of the LAW to provide advanced security orchestration and visualization.

Data Collection: Set up a Data Collection Rule (DCR) to monitor the specific file path: C:\programdata\failed_rdp.log.

3. The "Honeypot" Script (PowerShell)
Logic: The script runs in an infinite loop, querying the Windows Event Viewer specifically for Event ID 4625 (Failed Logon).

Enrichment: Extracted the Source IP from the event and sent a request to the IPGeolocation.io API.

Output: Formatted the results into a single string (Latitude, Longitude, Country, etc.) and appended it to the failed_rdp.log file.

4. Data Transformation (KQL)
Parsing: Since the logs arrived in Azure as a single "RawData" string, I authored KQL queries using the extract() function.
KQL Query USed
FAILED_RDP_MODERN_CL
| parse RawData with * "latitude:" Lat:double ",longitude:" Lon:double ",destinationhost:" * ",username:" * ",sourcehost:" IP:string ",state:" * ",country:" CountryName:string ",label:" MapLabel:string
| where isnotnull(Lat)
| summarize Attack_Count = count() by Lat, Lon, CountryName, MapLabel, IP
| project Lat, Lon, MapLabel, Attack_Count

Regex: Used regular expressions to "pull" the coordinates out of the text string so they could be mapped as numerical values.

5. Visualization (Azure Workbooks)
Mapping: Created a new Azure Workbook.

Heatmap: Used the processed coordinates to plot attacks on a global map, adjusting the Coloring Settings to "Heatmap" to visualize attack density by region.

Conclusion
This project demonstrates the speed at which exposed assets are discovered by automated threats. It highlights the importance of Network Security Groups (NSG) and the power of SIEM tools like Microsoft Sentinel in providing visibility into an organization's attack surface.
