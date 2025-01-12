# 6-CreateADGroups.ps1

$checkpointFile = "C:\SetupCheckpoint.txt"
$checkpoint = Get-Content -Path $checkpointFile

if ($checkpoint -eq "ADUsersCreated") {
    # Create AD groups and add members
    New-ADGroup -Name "MBstaff" -GroupScope Global
    New-ADGroup -Name "SKstaff" -GroupScope Global
    Add-ADGroupMember -Identity "MBstaff" -Members "Staff2", "Staff3", "Staff4"
    Add-ADGroupMember -Identity "SKstaff" -Members "Staff1"

    # Update checkpoint
    "ADGroupsCreated" | Out-File -FilePath $checkpointFile -Force
} else {
    Write-Host "AD groups already created or script interrupted."
}
