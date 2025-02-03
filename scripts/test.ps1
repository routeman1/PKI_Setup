#-------------------------[Initalization]-------------------------------

# NOTE: variables are read from the variables.csv file, and parsed from the menu script

#------------------------[Server Connectivity Test Loop]---------------------

Function InstallationTests {

    param (
    [array]$HostList,
    [string]$UserName
    )

$ComputerIP = $HostList

## Loop through and test session connectivity to each host (via IP address)
    Foreach ($ComputerIP in $ComputerIP) {  
        Write-Host "Testing PSSession connectivity to $ComputerIP"
        if (Test-PSSessionConnectivity -ComputerName $ComputerIP) {
            $condition = $true
            if ( $condition ) {
            Write-Host "- PSSession Connectivity successful."
        } }
            else {
            Write-Host "- PSSession Connectivity Failed to connect to $ComputerIP. Verify settings in the varible.txt file and ssh keys. 
            The script will not execute until this test passes." -ForegroundColor Red
            exit
        }

        # Write-Host "- Testing if user has required elevated permissions"
        # Returns $true if elevated, otherwise quit.
        # $permVal = ([bool] (net session 2>$null))
        # if ($permVal = $true )
        #     { Write-Host "  Passed - User has the required permissions" -ForegroundColor Green }
        # else {
        #     Write-Host "  Failed - The user " whoami " does not have the required elevated permissions on $ComputerIP." -ForegroundColor Red
        #     exit
        # }
    }
    Write-Host "All pre-installation tests have passed." -ForegroundColor Green
}


#------------------------[Test PSSession Connectivity]---------------------

# Function to test PSSession connectivity
Function Test-PSSessionConnectivity {

$maxRetries = 5
$retryInterval = 1 # in seconds

for ($i = 0; $i -lt $maxRetries; $i++) {
    try {
        # Try to create a PSSession
        $session = New-PSSession -HostName $ComputerIP -UserName $UserName -KeyFilePath "$sshKeyFile" -ErrorAction Stop

        # If successful, break out of the loop
        break
    }
    catch {
        Write-Warning "Failed to connect (attempt $($i + 1)). Retrying in $retryInterval seconds..."
        Start-Sleep -Seconds $retryInterval
    }
}

if ($session) {
        Write-Host "Connection successful!"
        # Do something with the session...
        Remove-PSSession $session 
        return $true
    } else {
        Write-Error "Failed to connect after $maxRetries attempts."
        return $false
    }
}


#------------------------[Server Connectivity Test Loop]---------------------

Function ServerTestLoop {
    param (
    [array]$HostList,
    [string]$UserName
    )

$ComputerIP = $HostList
## Loop through and test session connectivity to each host (via IP address)
    Foreach ($ComputerIP in $ComputerIP) {  
        Write-Host "Testing connectivity to $ComputerIP"
        if (Test-PSSessionConnectivity -ComputerName $ComputerIP) {
            $condition = $true
            if ( $condition ) {
            Write-Host "- Connectivity successful."
        } }
            else {
            Write-Host "- Connectivity failed. Verify settings in the varible.txt file and that all the host are up and running. 
            The script will not execute until this test passes."
            exit
        }
    }
}

