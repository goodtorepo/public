# Define checkpoint file and the script paths
$checkpointFile = "C:\SetupCheckpoint.txt"
$scriptPath1 = "C:\ADInstallScript1.ps1"
$scriptPath2 = "C:\ADTaskScript2.ps1"
$scriptPath3 = "C:\RestoreSettings3.ps1"

# Function to write the current step to the checkpoint file
function Set-Checkpoint {
    param (
        [string]$step
    )
    $step | Out-File -FilePath $checkpointFile -Force
}

# Function to read the last completed step from the checkpoint file
function Get-Checkpoint {
    if (Test-Path $checkpointFile) {
        Get-Content -Path $checkpointFile
    } else {
        "Start"
    }
}

# Function to configure auto-login and disable Ctrl+Alt+Del
function Configure-AutoLoginAndDisableCAD {
    $username = "Administrator"
    $password = "P@ssw0rd"

    # Disable Ctrl+Alt+Del requirement
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $regPath -Name DisableCAD -Value 1
    Write-Output "Ctrl+Alt+Del requirement disabled successfully."

    # Enable Auto-Login for Administrator
    Set-ItemProperty -Path $regPath -Name DefaultUserName -Value $username
    Set-ItemProperty -Path $regPath -Name DefaultPassword -Value $password
    Set-ItemProperty -Path $regPath -Name AutoAdminLogon -Value 1
    Set-ItemProperty -Path $regPath -Name ForceAutoLogon -Value 1
    Write-Output "Auto-login for user '$username' configured successfully."
}

# Function to create the scheduled task
function Create-ScheduledTask {
    param (
        [string]$scriptPath,
        [string]$taskName
    )
    
    # Check if the scheduled task already exists and remove it
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    # Create the scheduled task to run the script at logon
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$scriptPath`""
    $Trigger = New-ScheduledTaskTrigger -AtLogon
    Register-ScheduledTask -TaskName $taskName -Action $Action -Trigger $Trigger -Description "Run script at logon" -RunLevel Highest
    Write-Output "Scheduled task '$taskName' created successfully."
}

# Function to disable the scheduled task
function Disable-ScheduledTask {
    param (
        [string]$taskName
    )
    
    # Disable the specified scheduled task
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Output "Scheduled task '$taskName' has been disabled."
    }
}

# Function to promote server to Domain Controller
function Promote-ToDC {
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Restart
    Install-ADDSForest -DomainName "CDFC.local" -InstallDns -Force
    Set-Checkpoint "PromotedToDC"
}

# Function to set a static IP address
function Set-StaticIP {
    New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "10.10.10.34" -PrefixLength 27 -DefaultGateway "10.10.10.33"
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "10.10.10.34"
    Set-Checkpoint "StaticIPSet"
}

# Function to run the first script (ADInstallScript1.ps1)
function Run-ADInstallScript1 {
    Set-Checkpoint "RunningADInstallScript1"
    # Install Active Directory and promote to Domain Controller
    Promote-ToDC
    # Schedule the next task
    Create-ScheduledTask -scriptPath $scriptPath2 -taskName "RunADTaskScript2"
}

# Function to run the second script (ADTaskScript2.ps1)
function Run-ADTaskScript2 {
    Set-Checkpoint "RunningADTaskScript2"
    # Disable the scheduled task for the first script
    Disable-ScheduledTask -taskName "RunADInstallScript1"
    # Schedule the third script
    Create-ScheduledTask -scriptPath $scriptPath3 -taskName "RunRestoreSettings3"
}

# Function to run the third script (RestoreSettings3.ps1)
function Run-RestoreSettings3 {
    Set-Checkpoint "RunningRestoreSettings3"
    # Disable the auto-login and restore default settings
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $regPath -Name AutoAdminLogon -Value 0
    Set-ItemProperty -Path $regPath -Name ForceAutoLogon -Value 0
    Set-ItemProperty -Path $regPath -Name DefaultUserName -Value ""
    Set-ItemProperty -Path $regPath -Name DefaultPassword -Value ""
    # Disable the scheduled task for the third script
    Disable-ScheduledTask -taskName "RunRestoreSettings3"
    Write-Host "RestoreSettings3 has completed. All settings have been restored."
}

# Main script execution
$checkpoint = Get-Checkpoint

switch ($checkpoint) {
    "Start" {
        # Start the process by running the first script
        Run-ADInstallScript1
        break
    }
    "RunningADInstallScript1" {
        # Set static IP
        Set-StaticIP
        break
    }
    "StaticIPSet" {
        # Configure auto-login settings and create the task for the next script
        Configure-AutoLoginAndDisableCAD
        Start-Sleep -Seconds 10
        break
    }
    "RunningADTaskScript2" {
        # Run the second script logic and schedule the third script
        Run-ADTaskScript2
        break
    }
    "RunningRestoreSettings3" {
        # Run the third script to disable auto-logon and scheduled task
        Run-RestoreSettings3
        break
    }
}
