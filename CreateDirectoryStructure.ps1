# 7-CreateDirectoryStructure.ps1

$checkpointFile = "C:\SetupCheckpoint.txt"
$checkpoint = Get-Content -Path $checkpointFile

if ($checkpoint -eq "ADGroupsCreated") {
    # Create directory structure and set permissions
    $acl = Get-Acl C:\
    $acl.SetAccessRuleProtection($true, $false)
    Set-Acl C:\ $acl

    New-Item -Path "C:\Catalogue" -ItemType Directory
    $acl = Get-Acl "C:\Catalogue"
    $acl.SetOwner([System.Security.Principal.NTAccount]"Administrator")
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrator", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
    Set-Acl "C:\Catalogue" $acl

    New-Item -Path "C:\Catalogue\MB" -ItemType Directory
    $acl = Get-Acl "C:\Catalogue\MB"
    $acl.SetOwner([System.Security.Principal.NTAccount]"Administrator")
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrator", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
    Set-Acl "C:\Catalogue\MB" $acl

    # Update checkpoint
    "DirectoryStructureCreated" | Out-File -FilePath $checkpointFile -Force
} else {
    Write-Host "Directory structure creation already completed or script interrupted."
}
