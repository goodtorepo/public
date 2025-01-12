# Define the checkpoint file
$checkpointFile = "C:\SetupCheckpoint.txt"

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

# Function to configure AutoLogin and disable Ctrl+Alt+Del
function Configure-AutoLoginAndDisableCAD {
    $username = "Administrator"
    $password = "P@ssw0rd"  # Replace with the actual password

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

# Function to create Scheduled Task
function Create-ScheduledTask {
    $ScriptToRun = "C:\Path\To\Your\Script.ps1"  # Replace with actual path
    $TaskName = "RunAfterLogon"

    # Check if the scheduled task exists
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Write-Output "Task '$TaskName' already exists. Updating..."
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    # Create the action to run the script
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$ScriptToRun`""

    # Set the trigger to run at logon
    $Trigger = New-ScheduledTaskTrigger -AtLogon

    # Register the scheduled task
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Description "Runs a script after user logs into Windows" -RunLevel Highest
    Write-Output "Scheduled task '$TaskName' created successfully."
}

# Function to rename the server
function Rename-Server {
    param (
        [string]$newName
    )
    Rename-Computer -NewName $newName -Force
    Set-Checkpoint "Renamed"
    Restart-Computer -Force
}

# Function to set a static IP address
function Set-StaticIP {
    param (
        [string]$ipAddress,
        [string]$subnetMask,
        [string]$gateway,
        [string]$dnsServer
    )
    $interface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    New-NetIPAddress -InterfaceIndex $interface.InterfaceIndex -IPAddress $ipAddress -PrefixLength 27 -DefaultGateway $gateway
    Set-DnsClientServerAddress -InterfaceIndex $interface.InterfaceIndex -ServerAddresses $dnsServer
    Set-Checkpoint "StaticIP"
    Restart-Computer -Force
}

# Function to promote the server to a domain controller
function Promote-ToDC {
    param (
        [string]$domainName
    )
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Restart
    Install-ADDSForest -DomainName $domainName -InstallDns -Force
    Set-Checkpoint "PromotedToDC"
}

# Function to create AD users
function Create-ADUsers {
    param (
        [string]$filePath
    )
    $users = Import-Csv -Path $filePath
    foreach ($user in $users) {
        New-ADUser -Name $user.UserId -SamAccountName $user.UserId -UserPrincipalName "$($user.UserId)@$($env:USERDOMAIN)" -AccountPassword (ConvertTo-SecureString $user.Password -AsPlainText -Force) -Description $user.UserDescription -City $user.City -State $user.Prov -AccountExpirationDate $user.AccountExpiryDate -Enabled $true
    }
    Set-Checkpoint "ADUsersCreated"
}

# Function to create AD groups and add members
function Create-ADGroups {
    New-ADGroup -Name "MBstaff" -GroupScope Global
    New-ADGroup -Name "SKstaff" -GroupScope Global
    Add-ADGroupMember -Identity "MBstaff" -Members "Staff2", "Staff3", "Staff4"
    Add-ADGroupMember -Identity "SKstaff" -Members "Staff1"
    Set-Checkpoint "ADGroupsCreated"
}

# Function to create directory structure and set permissions
function Create-DirectoryStructure {
    $acl = Get-Acl C:\
    $acl.SetAccessRuleProtection($true, $false)
    Set-Acl C:\ $acl

    New-Item -Path "C:\Catalogue" -ItemType Directory
    $acl = Get-Acl "C:\Catalogue"
    $acl.SetOwner([System.Security.Principal.NTAccount]"Administrator")
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrator", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("MBstaff", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SKstaff", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Staff2", "Read", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Staff1", "Read", "ContainerInherit,ObjectInherit", "None", "Allow")))
    Set-Acl "C:\Catalogue" $acl

    New-Item -Path "C:\Catalogue\MB" -ItemType Directory
    $acl = Get-Acl "C:\Catalogue\MB"
    $acl.SetOwner([System.Security.Principal.NTAccount]"Administrator")
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrator", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("MBstaff", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
    Set-Acl "C:\Catalogue\MB" $acl

    Set-Checkpoint "DirectoryStructureCreated"
}

# Function to create a public folder that everyone can have read access to
function Create-PublicFolder {
    New-Item -Path "C:\Stuff" -ItemType Directory
    $acl = Get-Acl "C:\Stuff"
    $acl.SetAccessRuleProtection($true, $false)
    Set-Acl "C:\Stuff" $acl

    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Read", "ContainerInherit,ObjectInherit", "None", "Allow")))
    Set-Acl "C:\Stuff" $acl

    Set-Checkpoint "PublicFolderCreated"
}

# Function to create organizational units
function Create-OrganizationalUnits {
    New-ADOrganizationalUnit -Name "Supervisors"
    New-ADOrganizationalUnit -Name "Troubleshooters"
    Set-Checkpoint "OrganizationalUnitsCreated"
}

# Function to install FTP feature but keep it disabled
function Install-FTP {
    Install-WindowsFeature -Name Web-Ftp-Server
    Stop-Service -Name ftpsvc
    Set-Checkpoint "FTPInstalled"
}

# Main script execution
$checkpoint = Get-Checkpoint

switch ($checkpoint) {
    "Start" {
        Rename-Server "CDFCsvr"
        Start-Sleep -Seconds 5
        break
    }
    "Renamed" {
        Set-StaticIP "10.10.10.34" "255.255.255.224" "10.10.10.33" "10.10.10.34"
        Start-Sleep -Seconds 5
        break
    }
    "StaticIP" {
        Promote-ToDC "CDFC.local"
        Start-Sleep -Seconds 10
        break
    }
    "PromotedToDC" {
        Create-ADUsers "C:\users.csv"
        Start-Sleep -Seconds 5
        break
    }
    "ADUsersCreated" {
        Create-ADGroups
        Start-Sleep -Seconds 5
        break
    }
    "ADGroupsCreated" {
        Create-DirectoryStructure
        Start-Sleep -Seconds 5
        break
    }
    "DirectoryStructureCreated" {
        Create-PublicFolder
        Start-Sleep -Seconds 5
        break
    }
    "PublicFolderCreated" {
        Create-OrganizationalUnits
        Start-Sleep -Seconds 5
        break
    }
    "OrganizationalUnitsCreated" {
        Install-FTP
        Start-Sleep -Seconds 5
        break
    }
    "FTPInstalled" {
        Configure-AutoLoginAndDisableCAD
        Create-ScheduledTask
        Start-Sleep -Seconds 5
        Write-Host "Setup completed!"
        break
    }
}
