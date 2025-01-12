# 8-SetupCompleted.ps1

$checkpointFile = "C:\SetupCheckpoint.txt"
$checkpoint = Get-Content -Path $checkpointFile

if ($checkpoint -eq "DirectoryStructureCreated") {
    Write-Host "Setup completed successfully!"
} else {
    Write-Host "Setup not yet completed."
}
