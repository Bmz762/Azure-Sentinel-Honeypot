# Azure-Sentinel-Honeypot
<img width="1731" height="738" alt="honey_pot_HeatMap_v2" src="https://github.com/user-attachments/assets/0d56f0ee-8df5-4dd9-92c4-7b7e44d91442" />

Real time RDP attack visualization project with Azure Sentinel and KQL
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

Regex: Used regular expressions to "pull" the coordinates out of the text string so they could be mapped as numerical values.

5. Visualization (Azure Workbooks)
Mapping: Created a new Azure Workbook.

Heatmap: Used the processed coordinates to plot attacks on a global map, adjusting the Coloring Settings to "Heatmap" to visualize attack density by region.
