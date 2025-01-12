# MasterScript.ps1

# Function to check checkpoint and run steps
function Run-Setup {
    $checkpointFile = "C:\SetupCheckpoint.txt"
    $checkpoint = Get-Content -Path $checkpointFile

    # Step 1: Initialize checkpoint
    if ($checkpoint -eq "Start" -or -not (Test-Path $checkpointFile)) {
        Write-Host "Starting setup process..."
        .\1-CreateCheckpoint.ps1
        .\2-RenameServer.ps1
    }

    # Step 2: Rename Server
    if ($checkpoint -eq "Renamed") {
        .\3-SetStaticIP.ps1
    }

    # Step 3: Set Static IP
    if ($checkpoint -eq "StaticIP") {
        .\4-PromoteToDC.ps1
    }

    # Step 4: Promote to Domain Controller
    if ($checkpoint -eq "PromotedToDC") {
        .\5-CreateADUsers.ps1
    }

    # Step 5: Create AD Users
    if ($checkpoint -eq "ADUsersCreated") {
        .\6-CreateADGroups.ps1
    }

    # Step 6: Create AD Groups
    if ($checkpoint -eq "ADGroupsCreated") {
        .\7-CreateDirectoryStructure.ps1
    }

    # Step 7: Create Directory Structure
    if ($checkpoint -eq "DirectoryStructureCreated") {
        .\8-SetupCompleted.ps1
    }
}

# Run the full setup process
Run-Setup
