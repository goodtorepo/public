# 4-PromoteToDC.ps1

$checkpointFile = "C:\SetupCheckpoint.txt"
$checkpoint = Get-Content -Path $checkpointFile

if ($checkpoint -eq "StaticIP") {
    # Promote to Domain Controller
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Restart
    Install-ADDSForest -DomainName "example.com" -InstallDns -Force

    # Update checkpoint
    "PromotedToDC" | Out-File -FilePath $checkpointFile -Force
} else {
    Write-Host "Domain controller promotion already done or script interrupted."
}
