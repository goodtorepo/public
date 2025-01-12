# 3-SetStaticIP.ps1

$checkpointFile = "C:\SetupCheckpoint.txt"
$checkpoint = Get-Content -Path $checkpointFile

if ($checkpoint -eq "Renamed") {
    # Set static IP
    $interface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    New-NetIPAddress -InterfaceIndex $interface.InterfaceIndex -IPAddress "192.168.1.100" -PrefixLength 24 -DefaultGateway "192.168.1.1"
    Set-DnsClientServerAddress -InterfaceIndex $interface.InterfaceIndex -ServerAddresses "8.8.8.8"

    # Update checkpoint
    "StaticIP" | Out-File -FilePath $checkpointFile -Force
    Restart-Computer -Force
} else {
    Write-Host "Static IP already configured or script interrupted."
}
