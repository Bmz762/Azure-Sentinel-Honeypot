# Setup variables
$API_KEY      = 'API_KEY'
$LOGFILE_PATH = "C:\programdata\failed_rdp.log"

# Initialize the timestamp to grab events starting from RIGHT NOW
$lastCheckTime = Get-Date
write-host "Honeypot Script Started... Monitoring for failed RDP logins." -ForegroundColor Cyan
write-host "Log File: $LOGFILE_PATH" -ForegroundColor Gray

while($true) {
    # 1. Grab EVERY failed login (Event 4625) since the last loop check
    $Events = Get-WinEvent -LogName "Security" -FilterXml "*[System[(EventID=4625) and TimeCreated[@SystemTime > '$($lastCheckTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))']]]" -ErrorAction SilentlyContinue
    
    # Update the timestamp immediately so we don't double-count events in the next loop
    $lastCheckTime = Get-Date

    if ($Events) {
        write-host "New events detected! Processing..." -ForegroundColor Yellow
        foreach ($Event in $Events) {
            # Extract the IP Address from the Event XML
            $RemoteHost = ([xml]$Event.ToXml()).Event.EventData.Data | Where-Object {$_.Name -eq "IpAddress"} | Select-Object -ExpandProperty "#text"
            
            # Filter out empty IPs and localhost noise
            if ($RemoteHost -and $RemoteHost -ne "-" -and $RemoteHost -ne "127.0.0.1" -and $RemoteHost -ne "::1") {
                
                try {
                    # Call Geolocation API
                    $URL = "https://api.ipgeolocation.io/ipgeo?apiKey=$API_KEY&ip=$RemoteHost"
                    $Data = Invoke-RestMethod -Uri $URL
                    
                    # Only write to the log if we actually got a valid result from the API
                    if ($Data.latitude) {
                        $Output = "latitude:$($Data.latitude),longitude:$($Data.longitude),destinationhost:Resarch-Comp,username:anonymous,sourcehost:$RemoteHost,state:$($Data.state_prov),country:$($Data.country_name),label:$($Data.country_name) - $RemoteHost"
                        
                        # Append to file with UTF8 encoding
                        $Output | Out-File -FilePath $LOGFILE_PATH -Append -Encoding utf8
                        
                        write-host "ATTACK LOGGED: $RemoteHost from $($Data.country_name)" -ForegroundColor Red
                    } else {
                        write-host "API returned empty data for $RemoteHost (Likely Quota Limit)." -ForegroundColor Yellow
                    }
                } catch {
                    write-host "API Error or Request Limit Reached!" -ForegroundColor DarkYellow
                }
            }
        }
    }

    # Pulse check for the console
    write-host "Scanning... ($((Get-Date).ToString('HH:mm:ss'))) Standing by for 42s." -ForegroundColor Gray
    Start-Sleep -Seconds 42
}
