# 5-CreateADUsers.ps1

$checkpointFile = "C:\SetupCheckpoint.txt"
$checkpoint = Get-Content -Path $checkpointFile

if ($checkpoint -eq "PromotedToDC") {
    # Create AD users
    $users = Import-Csv -Path "C:\users.csv"
    foreach ($user in $users) {
        New-ADUser -Name $user.UserId -SamAccountName $user.UserId -UserPrincipalName "$($user.UserId)@$($env:USERDOMAIN)" `
            -AccountPassword (ConvertTo-SecureString $user.Password -AsPlainText -Force) `
            -Description $user.UserDescription -City $user.City -State $user.Prov `
            -AccountExpirationDate $user.AccountExpiryDate -Enabled $true
    }

    # Update checkpoint
    "ADUsersCreated" | Out-File -FilePath $checkpointFile -Force
} else {
    Write-Host "AD users creation already completed or script interrupted."
}
