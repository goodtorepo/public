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
        New-ADUser -Name $user.Userid -SamAccountName $user.Userid -UserPrincipalName "$($user.Userid)@$($env:USERDOMAIN)" `
            -AccountPassword (ConvertTo-SecureString $user.Password -AsPlainText -Force) `
            -Description $user.UserDescription `
            -City $user.City `
            -State $user.Prov `
            -AccountExpirationDate $user.AccountExpiryDate `
            -Enabled $true
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

    # Create C:\Catalogue
    New-Item -Path "C:\Catalogue" -ItemType Directory
    $acl = Get-Acl "C:\Catalogue"
    $acl.SetOwner([System.Security.Principal.NTAccount]"Administrator")
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrator", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("MBstaff", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SKstaff", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
    Set-Acl "C:\Catalogue" $acl

    # Create C:\Catalogue\MB
    New-Item -Path "C:\Catalogue\MB" -ItemType Directory
    $acl = Get-Acl "C:\Catalogue\MB"
    $acl.SetOwner([System.Security.Principal.NTAccount]"Administrator")
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrator", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("MBstaff", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Staff2", "Read", "ContainerInherit,ObjectInherit", "None", "Allow")))
    Set-Acl "C:\Catalogue\MB" $acl

    # Create C:\Catalogue\SK
    New-Item -Path "C:\Catalogue\SK" -ItemType Directory
    $acl = Get-Acl "C:\Catalogue\SK"
    $acl.SetOwner([System.Security.Principal.NTAccount]"Administrator")
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrator", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SKstaff", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Staff1", "Read", "ContainerInherit,ObjectInherit", "None", "Allow")))
    Set-Acl "C:\Catalogue\SK" $acl

    Set-Checkpoint "DirectoryStructureCreated"
}

# Function to create a public folder
function Create-PublicFolder {
    New-Item -Path "C:\Stuff" -ItemType Directory
    $acl = Get-Acl "C:\Stuff"
    $acl.SetOwner([System.Security.Principal.NTAccount]"Administrator")
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Read", "ContainerInherit,ObjectInherit", "None", "Allow")))
    Set-Acl "C:\Stuff" $acl
    Write-Output "Public folder created successfully."
}

# Function to create Organizational Units
function Create-OrganizationalUnits {
    New-ADOrganizationalUnit -Name "Supervisors" -Path "DC=CDFC,DC=local"
    New-ADOrganizationalUnit -Name "Troubleshooters" -Path "DC=CDFC,DC=local"
    Write-Output "Organizational Units created."
}

# Function to install FTP and disable it
function Install-FTP {
    Install-WindowsFeature -Name Web-Ftp-Server
    Set-Service -Name "ftpsvc" -StartupType Disabled
    Write-Output "FTP installed and disabled."
}

# Main script execution
$checkpoint = Get-Checkpoint

switch ($checkpoint) {
    "Start" {
        Rename-Server "CDFCsvr"
        break
    }
    "Renamed" {
        Set-StaticIP "10.10.10.34" "255.255.255.224" "10.10.10.33" "10.10.10.34"
        break
    }
    "StaticIP" {
        Promote-ToDC "CDFC.local"
        break
    }
    "PromotedToDC" {
        Create-ADUsers "C:\users.txt"
        break
    }
    "ADUsersCreated" {
        Create-ADGroups
        break
    }
    "ADGroupsCreated" {
        Create-DirectoryStructure
        break
    }
    "DirectoryStructureCreated" {
        Create-PublicFolder
        break
    }
    "PublicFolderCreated" {
        Create-OrganizationalUnits
        break
    }
    "OrganizationalUnitsCreated" {
        Install-FTP
        break
    }
    "FTPInstalled" {
        Write-Host "Setup completed!"
        break
    }
}
