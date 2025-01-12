# 1-CreateCheckpoint.ps1

$checkpointFile = "C:\SetupCheckpoint.txt"

# Initialize checkpoint file if it doesn't exist
if (-not (Test-Path $checkpointFile)) {
    "Start" | Out-File -FilePath $checkpointFile
} else {
    Write-Host "Checkpoint file already exists."
}
