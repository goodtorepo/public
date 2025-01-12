# 2-RenameServer.ps1

$checkpointFile = "C:\SetupCheckpoint.txt"
$checkpoint = Get-Content -Path $checkpointFile

if ($checkpoint -eq "Start") {
    # Rename server
    Rename-Computer -NewName "NewServerName" -Force
    # Update checkpoint
    "Renamed" | Out-File -FilePath $checkpointFile -Force
    Restart-Computer -Force
} else {
    Write-Host "Rename already completed or script interrupted."
}
