#-------------------------[Initalization]-------------------------------

# SSH Key file path (Note: this is the path on the client & needs to be the private key
$sshKeyFile = "~/.ssh/pkisetup"


# Read the variables from the variables.csv comma delimited file. Ignore lines that start with #
Get-Content variables.csv | Where-Object {$_.length -gt 0} | Where-Object {!$_.StartsWith("#")} | ForEach-Object {

    $var = $_.Split(',',2).Trim()
    New-Variable -Scope Script -Name $var[0] -Value $var[1]

    }

# build host data arrays
$DC1 = @($DC1_Host_Name, $DC1_Host_IPAddress)
$DC2 = @($DC2_Host_Name, $DC2_Host_IPAddress)
$RCA = @($RCA_Host_Name, $RCA_Host_IPAddress)
$ICA = @($ICA_Host_Name, $ICA_Host_IPAddress)

# Define Secure Variables for Passwords
$secureDefWinLoginPass = ConvertTo-SecureString $DefWinLoginPass -AsPlainText -force 
$secureNewAdminPass = ConvertTo-SecureString $NewAdminPass -AsPlainText -force
$secureNewGuestPass = ConvertTo-SecureString $NewGuestPass -AsPlainText -force
$secureRemoteAdminPass = ConvertTo-SecureString $RemoteAdminPass -AsPlainText -force


#----------------------------Main Menu-----------------------------
function Show-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "Main Menu" -ForegroundColor Yellow
    Write-Host "---------"
    Write-Host ""
    Write-Host "1. Install and Configure DC01 with Active Directory Services"  
    Write-Host "2. Install and Configure Offline Root CA"
    Write-Host "3. Install and Configure a Domain Intermediate Certificate Server"
    Write-Host ""
    Write-Host "A. Run 1-3 consecutively"
    Write-Host ""
    Write-Host "4. Final Configuration"
    Write-Host ""
    Write-Host "---------"
    Write-Host ""
    Write-Host "Q. Quit"
    Write-Host ""
}

while ($true) {
    Show-Menu
    $choice = Read-Host "Enter your choice"

    switch ($choice) {
        "1" {
            & ".\domain_config.ps1"
            Write-Progress -Activity "Clearing status bar" -Completed 
            Read-Host -Prompt "Press any key to continue" | Out-Null
            break
        }
        "2" {
            & ".\rca_setup.ps1" 
            Write-Progress -Activity "Clearing status bar" -Completed
            Read-Host -Prompt "Press any key to continue" | Out-Null
            break
        }
        "3" {
            & ".\ica_setup.ps1"
            Write-Progress -Activity "Clearing status bar" -Completed
            Read-Host -Prompt "Press any key to continue" | Out-Null
            break
        }
        "A" {
            & ".\domain_config.ps1"
            & ".\rca_setup.ps1"
            & ".\ica_setup.ps1"
            Write-Progress -Activity "Clearing status bar" -Completed
            Read-Host -Prompt "Press any key to continue" | Out-Null
            break
        }
        "4" {
            & ".\final_config.ps1" 
            Write-Progress -Activity "Clearing status bar" -Completed
            Read-Host -Prompt "Press any key to continue" | Out-Null
            break
        }
        "Q" {
            exit
        }
        default {
            Write-Host "Invalid choice."
        }
    }
}