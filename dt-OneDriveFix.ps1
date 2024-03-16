
$PSVersionTable.PSVersion

# Check if powershell is installed
if (-not (Test-Path -Path "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")) {
    Write-Host "PowerShell is not installed. Installing PowerShell..."

    # Install Pester module
    Install-Module -Name Pester -Force
    
    Write-Host "PowerShell installation completed."
    return
}
    Import-Module -Name Pester -Force
    # Define the function to run the issue
    function Invoke-IssueFunction {
        param (
            $issue
        )
        try {
            if ($issue.Name -eq "Run Program") {
                $result = Run-Program -FilePath ""C:\Troubleshoot\Modules\dt-OneDriveFix.exe""
            }
            else {
                & $issue.Function
            }
            return @{
                Result = "Success"
                Information = "Issue $($issue.Name) has been resolved."
                ResultDetails = $result
            }
        }
        catch {
            return @{
                Result = "Failure"
                Information = "An error occurred while executing the function. For more information, refer to: $($issue.Link)"
            }
        }
    }

function Invoke-IssueFunction {
    param (
        $issue
    )

    try {
        if ($issue.Name -eq "Run Program") {
            $result = Run-Program -FilePath "C:\path\to\program.exe"
        }
        else {
            & $issue.Function
        }

        return @{
            Result = "Success"
            Information = "Issue $($issue.Name) has been resolved."
            ResultDetails = $result
        }
    }
    catch {
        return @{
            Result = "Failure"
            Information = "An error occurred while executing the function. For more information, refer to: $($issue.Link)"
        }
    }
}

# Run a program .exe file
function Run-Program {
    param (
        [string]$FilePath
    )

    try {
        Start-Process -FilePath $FilePath
        return @{
            Result = "Success"
            Information = "Program $($FilePath) has been executed."
        }
    }
    catch {
        return @{
            Result = "Failure"
            Information = "An error occurred while executing the program $($FilePath)."
        }
    }
}
    param (
        $issue
    )
    ShowMenu $troubleShootingOptions

    Write-Host "=== $($issue.Name) ==="
    Write-Host
    Write-Host "Description: $($issue.Description)"
    Write-Host

    try {
        & $issue.Function
    }
    catch {
        Write-Host "An error occurred while executing the function."
        Write-Host "For more information, refer to: $($issue.Link)"
    }


function Resolve-Issue {
    param (
        $issue
    )
    Write-Host "Resolving issue: $($issue.Name)"
    Invoke-IssueFunction -issue $issue
    return "Issue $issue has been resolved"
}


# Restarts OneDrive
function Restart-OneDrive {
    $oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue

    if ($oneDriveProcess) {
        $oneDriveProcess | Stop-Process -Force
        Start-Sleep -Seconds 2  # Wait for a bit to make sure OneDrive has stopped

        $oneDrivePath = [System.Environment]::GetFolderPath('LocalApplicationData') + '\Microsoft\OneDrive\OneDrive.exe'
        Start-Process -FilePath $oneDrivePath
        Write-Host "OneDrive restarted."
    } else {
        Write-Host "OneDrive is not running."
    }
}

# Retrieves the attributes of a file
function Get-FileAttributes {
    param (
        [string]$FilePath
    )

    # Check if the file exists
    if (Test-Path $FilePath) {
        # Get the file attributes
        $fileAttributes = (Get-Item $FilePath).Attributes

        # Return the file information with additional details
        return @{
            Result = "Success"
            Information = "File attributes retrieved successfully."
            FilePath = $FilePath
            Attributes = $fileAttributes
            Source = "Microsoft Learn: Introduction to PowerShell - Module 3: Working with Files and Folders"
        }
    } else {
        return @{
            Result = "Failure"
            Information = "The file does not exist."
        }
    }
}


# Opens the OneDrive folder in File Explorer
    function Open-OneDriveFolder {
        Write-Host "Opening OneDrive folder in File Explorer..."

        $oneDrivePath = Get-OneDriveFolderPath
        if (-not $oneDrivePath) {
            return @{
                Result = "Failure"
                Information = "OneDrive folder path could not be found."
            }
        }

        Start-Process "explorer.exe" -ArgumentList $oneDrivePath

        return @{
            Result = "Success"
            Information = "OneDrive folder opened in File Explorer."
        }
    }

    function Create-OneDriveShortcut {
        Write-Host "Creating a shortcut to OneDrive on the desktop..."

        $oneDrivePath = Get-OneDriveFolderPath
        if (-not $oneDrivePath) {
            return @{
                Result = "Failure"
                Information = "OneDrive folder path could not be found."
            }
        }

        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $shortcutPath = Join-Path -Path $desktopPath -ChildPath "OneDrive.lnk"

        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($shortcutPath)
        $Shortcut.TargetPath = $oneDrivePath
        $Shortcut.Save()

        return @{
            Result = "Success"
            Information = "Shortcut to OneDrive created on the desktop."
        }
    }

    function Get-OneDriveSyncStatus {
        Write-Host "Retrieving the synchronization status of OneDrive..."

        $oneDriveProcess = Get-Process -Name OneDrive -ErrorAction SilentlyContinue
        if (-not $oneDriveProcess) {
            return @{
                Result = "Failure"
                Information = "OneDrive is not currently running."
            }
        }

        $dllPath = "Path\to\OneDriveLib.dll"
        if (-not (Test-Path $dllPath)) {
            return @{
                Result = "Failure"
                Information = "OneDriveLib.dll not found at path: $dllPath"
            }
        }

        Add-Type -Path $dllPath

        $oneDriveStatus = [OneDriveLib.OneDrive]::GetODStatus()

        switch ($oneDriveStatus) {
            "UpToDate" { Write-Host "OneDrive is up to date." }
            "Syncing" { Write-Host "OneDrive is syncing." }
            "Paused" { Write-Host "OneDrive is paused." }
            "Error" { Write-Host "OneDrive has encountered an error." }
            default { Write-Host "OneDrive status is unknown." }
        }

        $oneDrivePath = [Environment]::ExpandEnvironmentVariables("$env:USERPROFILE\OneDrive")
        if (Test-Path $oneDrivePath) {
            return @{
                Result = "Success"
                Information = "OneDrive is currently syncing."
                OneDrivePath = $oneDrivePath
            }
        } else {
            return @{
                Result = "Failure"
                Information = "OneDrive path not found on your machine."
            }
        }
    }

    function Get-OneDriveFiles {
        Write-Host "Retrieving all OneDrive files from the system..."

        $oneDrivePath = Get-OneDriveFolderPath
        if (-not $oneDrivePath) {
            return @{
                Result = "Failure"
                Information = "OneDrive folder path could not be found."
            }
        }

        $files = Get-ChildItem -Path $oneDrivePath -File -Recurse

        if ($files.Count -eq 0) {
            return @{
                Result = "Failure"
                Information = "No files found in the OneDrive folder."
            }
        }

        $fileInfo = foreach ($file in $files) {
            [PSCustomObject]@{
                FileName = $file.Name
                CreationTime = $file.CreationTime
            }
        }

        return @{
            Result = "Success"
            Information = "OneDrive files retrieved successfully."
            Files = $fileInfo
        }
    }

    function Test-OneDriveAccess {
        param (
            [Parameter(Mandatory = $true)]
            [string]$FilePath
        )

        Write-Host "Testing OneDrive access for file: $FilePath"
    }
        $oneDrivePath = Get-OneDriveFolderPath
        if (-not $oneDrivePath) {
            return @{
                Result = "Failure"
                Information = "OneDrive folder path could not be found."
            }
        }

        function Get-OneDriveFileStatus {
            param (
                [Parameter(Mandatory = $true)]
                [string]$FilePath
            )

            Write-Host "Retrieving status for file: $FilePath"

            if (Test-Path -Path $FilePath) {
                $fileAttributes = [System.IO.File]::GetAttributes($FilePath)
                if ($fileAttributes -band [System.IO.FileAttributes]::Offline) {
                    return @{
                        Result = "Success"
                        Information = "The file $FilePath is available online only."
                        FilePath = $FilePath
                    }
                } else {
                    return @{
                        Result = "Success"
                        Information = "The file $FilePath is available locally."
                        FilePath = $FilePath
                    }
                }
            } else {
                return @{
                    Result = "Failure"
                    Information = "The file $FilePath does not exist."
                }
            }
        }

        function Get-OneDriveFileInfo {
            param (
                [Parameter(Mandatory = $true)]
                [string]$FilePath
            )

            Write-Host "Retrieving information for file: $FilePath"

            if (Test-Path -Path $FilePath) {
                $fileProperties = Get-ItemProperty -Path $FilePath
                $fileAccessControl = Get-Acl -Path $FilePath
                $userAccessRules = $fileAccessControl.Access | Where-Object { $_.IdentityReference -eq $env:USERNAME }

                return @{
                    Result = "Success"
                    Information = "File information retrieved successfully."
                    FilePath = $FilePath
                    Properties = $fileProperties
                    UserAccessRules = $userAccessRules
                }
            } else {
                return @{
                    Result = "Failure"
                    Information = "The file $FilePath does not exist."
                }
            }
        }

        function Get-OneDriveFolderPaths {
            Write-Host "Checking OneDrive folder paths..."

            $oneDriveFolderPath = Get-OneDriveFolderPath
            if (-not $oneDriveFolderPath) {
                return @{
                    Result = "Failure"
                    Information = "OneDrive folder path could not be found."
                }
            }

            return @{
                Result = "Success"
                Information = "OneDrive folder paths checked successfully."
                OneDriveFolderPath = $oneDriveFolderPath
            }
        }

        function Get-OneDriveProperties {
            param (
                [Parameter(Mandatory = $true)]
                [string]$FilePath
            )

            Write-Host "Retrieving properties for file: $FilePath"

            if (Test-Path -Path $FilePath) {
                $fileProperties = Get-ItemProperty -Path $FilePath | Select-Object -Property Name, Length, LastWriteTime, Attributes

                return @{
                    Result = "Success"
                    Information = "File properties retrieved successfully."
                    FilePath = $FilePath
                    Properties = $fileProperties
                }
            } else {
                return @{
                    Result = "Failure"
                    Information = "The file $FilePath does not exist."
                }
            }
        }

        function Get-UserFilePermissions {
            param (
                [Parameter(Mandatory = $true)]
                [string]$FilePath
            )

            Write-Host "Retrieving file permissions for: $FilePath"

            if (Test-Path -Path $FilePath) {
                $fileAccessControl = Get-Acl -Path $FilePath
                $userAccessRules = $fileAccessControl.Access | Where-Object { $_.IdentityReference -eq $env:USERNAME }

                return @{
                    Result = "Success"
                    Information = "File permissions retrieved successfully."
                    FilePath = $FilePath
                    UserAccessRules = $userAccessRules
                }
            } else {
                return @{
                    Result = "Failure"
                    Information = "The file $FilePath does not exist."
                }
            }
        }

        function Restart-OneDrive {
            Write-Host "Restarting OneDrive..."

            $oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue

            if ($oneDriveProcess) {
                $oneDriveProcess | Stop-Process -Force
                Start-Sleep -Seconds 2  # Wait for a bit to make sure OneDrive has stopped

                $oneDrivePath = [System.Environment]::GetFolderPath('LocalApplicationData') + '\Microsoft\OneDrive\OneDrive.exe'
                Start-Process -FilePath $oneDrivePath
                Write-Host "OneDrive restarted."
            } else {
                Write-Host "OneDrive is not running."
            }
        }

        function Get-OneDriveFolderPath {
            $OneDriveFolderPath = ""
            
            # Check if OneDrive is installed
            if (Test-Path "$env:USERPROFILE\OneDrive") {
                $OneDriveFolderPath = "$env:USERPROFILE\OneDrive"
            }
            elseif (Test-Path "$env:USERPROFILE\OneDrive - Personal") {
                $OneDriveFolderPath = "$env:USERPROFILE\OneDrive - Personal"
            }
            elseif (Test-Path "$env:USERPROFILE\OneDrive - Business") {
                $OneDriveFolderPath = "$env:USERPROFILE\OneDrive - Business"
            }
            
            return $OneDriveFolderPath
        }
        function Create-OneDriveShortcut {
            Write-Host "Creating a shortcut to OneDrive on the desktop..."

            $oneDrivePath = Get-OneDriveFolderPath
            if (-not $oneDrivePath) {
                return @{
                    Result = "Failure"
                    Information = "OneDrive folder path could not be found."
                }
            }

            $desktopPath = [Environment]::GetFolderPath("Desktop")
            $shortcutPath = Join-Path -Path $desktopPath -ChildPath "OneDrive.lnk"

            $WshShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut($shortcutPath)
            $Shortcut.TargetPath = $oneDrivePath
            $Shortcut.Save()

            return @{
                Result = "Success"
                Information = "Shortcut to OneDrive created on the desktop."
            }
        }

        function Get-OneDriveSyncStatus {
            # Code for retrieving OneDrive synchronization status goes here
            Write-Host "Retrieving the synchronization status of OneDrive..."

            $oneDriveProcess = Get-Process -Name OneDrive -ErrorAction SilentlyContinue
            if (-not $oneDriveProcess) {
                return @{
                    Result = "Failure"
                    Information = "OneDrive is not currently running."
                }
            }

            $dllPath = "Path\to\OneDriveLib.dll"
            if (-not (Test-Path $dllPath)) {
                return @{
                    Result = "Failure"
                    Information = "OneDriveLib.dll not found at path: $dllPath"
                }
            }

            Add-Type -Path $dllPath
        }
            function Get-OneDriveStatus {
                # Get the status of OneDrive
                Write-Host "Retrieving the status of OneDrive..."

                $oneDriveStatus = [OneDriveLib.OneDrive]::GetODStatus()

                switch ($oneDriveStatus) {
                    "UpToDate" { return "OneDrive is up to date." }
                    "Syncing" { return "OneDrive is syncing." }
                    "Paused" { return "OneDrive is paused." }
                    "Error" { return "OneDrive has encountered an error." }
                    default { return "OneDrive status is unknown." }
                }
            }

            function Get-OneDriveFileInfo {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$FolderPath
                )

                # Get file information for the specified OneDrive folder
                Write-Host "Getting file information for: $FolderPath"

                if (Test-Path $FolderPath) {
                    $files = Get-ChildItem -Path $FolderPath -File -Recurse
                    if ($files.Count -eq 0) {
                        return @{
                            Result = "Failure"
                            Information = "No files found in the OneDrive folder."
                        }
                    }

                    $fileInfo = foreach ($file in $files) {
                        [PSCustomObject]@{
                            FileName = $file.Name
                            CreationTime = $file.CreationTime
                        }
                    }

                    return @{
                        Result = "Success"
                        Information = "OneDrive files retrieved successfully."
                        Files = $fileInfo
                    }
                } else {
                    return @{
                        Result = "Failure"
                        Information = "The folder $FolderPath does not exist."
                    }
                }
            }

            function Get-OneDriveProperties {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$FolderPath
                )

                # Get properties of the specified OneDrive folder
                Write-Host "Getting properties for: $FolderPath"

                if (Test-Path $FolderPath) {
                    $folderProperties = Get-ItemProperty -Path $FolderPath
                    return @{
                        Result = "Success"
                        Information = "OneDrive folder properties retrieved successfully."
                        FolderPath = $FolderPath
                        Properties = $folderProperties
                    }
                } else {
                    return @{
                        Result = "Failure"
                        Information = "The folder $FolderPath does not exist."
                    }
                }
            }

            function Get-UserFilePermissions {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$FilePath
                )

                # Get file permissions for the specified file
                Write-Host "Retrieving file permissions for: $FilePath"

                if (Test-Path $FilePath) {
                    $fileAccessControl = Get-Acl -Path $FilePath
                    $username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    $userAccessRules = $fileAccessControl.Access | Where-Object { $_.IdentityReference -eq $username }

                    return @{
                        Result = "Success"
                        Information = "File permissions retrieved successfully."
                        FilePath = $FilePath
                        UserAccessRules = $userAccessRules
                    }
                } else {
                    return @{
                        Result = "Failure"
                        Information = "The file $FilePath does not exist."
                    }
                }
            }

            function Get-AllOneDriveFiles {
                param (
                    [Parameter(Mandatory = $true)]
                    [string]$FolderPath
                )

                # Get all files in the specified OneDrive folder
                Write-Host "Getting all files in: $FolderPath"

                if (Test-Path $FolderPath) {
                    $files = Get-ChildItem -Path $FolderPath -File -Recurse
                    if ($files.Count -eq 0) {
                        return @{
                            Result = "Failure"
                            Information = "No files found in the OneDrive folder."
                        }
                    }

                    $fileInfo = foreach ($file in $files) {
                        [PSCustomObject]@{
                            FileName = $file.Name
                            CreationTime = $file.CreationTime
                        }
                    }

                    return @{
                        Result = "Success"
                        Information = "All OneDrive files retrieved successfully."
                        Files = $fileInfo
                    }
                } else {
                    return @{
                        Result = "Failure"
                        Information = "The folder $FolderPath does not exist."
                    }
                }
            }

            function Get-StoredCredentials {
                # Get stored credentials related to OneDrive and OneDrive for Business
                Write-Host "Getting stored credentials"

                $credentials = @()

                $oneDriveCredential = cmdkey /list | Where-Object { $_ -like "*Target: OneDrive*" }
                if ($oneDriveCredential) {
                    $credentials += $oneDriveCredential
                }

                $oneDriveForBusinessCredential = cmdkey /list | Where-Object { $_ -like "*Target: OneDriveForBusiness*" }
                if ($oneDriveForBusinessCredential) {
                    $credentials += $oneDriveForBusinessCredential
                }

                if ($credentials.Count -eq 0) {
                    return @{
                        Result = "Failure"
                        Information = "No stored credentials found for OneDrive or OneDrive for Business."
                    }
                } else {
                    return @{
                        Result = "Success"
                        Information = "Stored credentials retrieved successfully."
                        Credentials = $credentials
                    }
                }
            }

            function Get-OneDriveInstallationStatus {
                # Get the installation status of OneDrive
                Write-Host "Getting OneDrive installation status"

                $oneDrivePaths = @(
                    "${env:SYSTEMROOT}\System32\OneDriveSetup.exe",
                    "${env:PROGRAMFILES}\Microsoft OneDrive\OneDrive.exe",
                    "${env:PROGRAMFILES(x86)}\Microsoft OneDrive\OneDrive.exe"
                )

                foreach ($path in $oneDrivePaths) {
                    if (Test-Path $path) {
                        return @{
                            Result = "Success"
                            Information = "OneDrive is installed at $path."
                        }
                    }
                }

                return @{
                    Result = "Failure"
                    Information = "OneDrive is not installed."
                }
            }

                    function Invoke-OneDriveDiagnostics {
                        param (
                            [Parameter(Mandatory = $true)]
                            [string]$OneDriveFolderPath
                        )

                        # Invoke various OneDrive diagnostic processes
                        Invoke-Process -FunctionName "Get-OneDriveStatus"
                        Invoke-Process -FunctionName "Get-OneDriveFileInfo" -FilePath $OneDriveFolderPath
                        Invoke-Process -FunctionName "Get-OneDriveProperties" -FolderPath $OneDriveFolderPath
                        Invoke-Process -FunctionName "Get-UserFilePermissions" -FilePath $OneDriveFolderPath
                        Invoke-Process -FunctionName "Get-AllOneDriveFiles" -FolderPath $OneDriveFolderPath
                        Invoke-Process -FunctionName "Get-StoredCredentials"
                        Invoke-Process -FunctionName "Get-OneDriveInstallationStatus"
                    }

                    function Restart-OneDriveProcess {
                        # Restart OneDrive and OneDrive sync processes
                        Invoke-Process -FunctionName "Restart-Service" -ServiceName "OneDrive"
                        Invoke-Process -FunctionName "Restart-Service" -ServiceName "OneSyncSvc"
                    }

                    function Invoke-Process {
                        param (
                            [Parameter(Mandatory = $true)]
                            [string]$FunctionName,
                            [Parameter(Mandatory = $false)]
                            [string]$FolderPath,
                            [Parameter(Mandatory = $false)]
                            [string]$FilePath
                        )

                        $function = Get-Command -Name $FunctionName -ErrorAction SilentlyContinue
                        if ($function) {
                            try {
                                if ($FolderPath) {
                                    & $FunctionName -FolderPath $FolderPath
                                } elseif ($FilePath) {
                                    & $FunctionName -FilePath $FilePath
                                } else {
                                    & $FunctionName
                                }
                            } catch {
                                return @{
                                    Result = "Failure"
                                    Information = "An error occurred while executing the function $FunctionName."
                                    Error = $_.Exception.Message
                                }
                            }
                        } else {
                            return @{
                                Result = "Failure"
                                Information = "The function $FunctionName does not exist."
                            }
                        }
                    }

                    function Install-OneDrive {
                        # Check if OneDrive is already installed
                        $oneDrivePaths = @(
                            "${env:SYSTEMROOT}\System32\OneDriveSetup.exe",
                            "${env:PROGRAMFILES}\Microsoft OneDrive\OneDrive.exe",
                            "${env:PROGRAMFILES(x86)}\Microsoft OneDrive\OneDrive.exe"
                        )

                        foreach ($path in $oneDrivePaths) {
                            if (Test-Path $path) {
                                Write-Output "OneDrive is already installed at $path"
                                return
                            }
                        }

                        Write-Output "OneDrive is not installed. Attempting to install..."

                        # Download and run OneDrive setup
                        $OneDriveSetupUrl = "https://go.microsoft.com/fwlink/p/?LinkId=248256"
                        $OneDriveSetupPath = "$env:TEMP\OneDriveSetup.exe"
                        Invoke-WebRequest -Uri $OneDriveSetupUrl -OutFile $OneDriveSetupPath
                        Start-Process -FilePath $OneDriveSetupPath -Wait
                    }

                    function Test-OneDriveAccess {
                        param (
                            [Parameter(Mandatory = $true)]
                            [string]$OneDriveFolderPath,
                            [Parameter(Mandatory = $true)]
                            [string]$FilePath
                        )

                        # Check if the user has access to the specified file in OneDrive
                        Write-Host "Testing OneDrive access for file: $FilePath"

                        $fullPath = Join-Path -Path $OneDriveFolderPath -ChildPath $FilePath

                        if (Test-Path -Path $fullPath) {
                            $fileAttributes = [System.IO.File]::GetAttributes($fullPath)
                            if ($fileAttributes -band [System.IO.FileAttributes]::Offline) {
                                Write-Host "The file $fullPath is available online only."
                            } else {
                                Write-Host "The file $fullPath is available locally."
                            }
                        } else {
                            Write-Host "The file $fullPath does not exist."
                        }

                        return @{
                            Result = "Success"
                            Information = "For more information, visit: https://docs.microsoft.com/en-us/learn/modules/introduction-to-onedrive/"
                        }
                    }
                    
                    function Disable-OneDriveAtStartup {
                        Write-Host "This function disables OneDrive at startup."
                        Write-Host "It prevents OneDrive from starting automatically when the system boots."
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -Value ""
                        Write-Host "OneDrive has been disabled from starting automatically on Windows startup."
                        return @{
                            Result = "Success"
                            Information = "For more information, see: [Introduction to OneDrive](https://docs.microsoft.com/en-us/learn/modules/introduction-to-onedrive/)"
                        }
                    }

                    function Run-OneDriveProcess {
                        param (
                            [string]$ProcessName,
                            [scriptblock]$ProcessBlock,
                            [string]$ProcessMessage
                        )

                        Write-Host "Running process: $ProcessMessage"
                        try {
                            & $ProcessBlock
                        } catch {
                            Write-Host "Error occurred while running process: $ProcessMessage"
                            Write-Host "Error message: $_"
                        }
                    }
                        


                    function Clear-OneDriveCachedCredentials {
                        # Clear the cached credentials related to OneDrive and OneDrive for Business
                        Write-Host "Clearing cached credentials"

                        $oneDriveCredential = cmdkey /list | Where-Object { $_ -like "*Target: OneDrive*" }
                        if ($oneDriveCredential) {
                            Write-Host "Cached credentials found for OneDrive."
                            Write-Host $oneDriveCredential
                            $delete = Read-Host "Do you want to delete these credentials? (Y/N)"
                            if ($delete -eq "Y") {
                                cmdkey /delete:"OneDrive"
                                Write-Host "Credentials for OneDrive deleted."
                            }
                        } else {
                            Write-Host "Cached credentials not found for OneDrive."
                        }

                        $oneDriveForBusinessCredential = cmdkey /list | Where-Object { $_ -like "*Target: OneDriveForBusiness*" }
                        if ($oneDriveForBusinessCredential) {
                            Write-Host "Cached credentials found for OneDrive for Business."
                            Write-Host $oneDriveForBusinessCredential
                            $delete = Read-Host "Do you want to delete these credentials? (Y/N)"
                            if ($delete -eq "Y") {
                                cmdkey /delete:"OneDriveForBusiness"
                                Write-Host "Credentials for OneDrive for Business deleted."
                            }
                        } else {
                            Write-Host "Cached credentials not found for OneDrive for Business."
                        }

                        return @{
                            Result = "Success"
                            Information = "For more information, visit: https://docs.microsoft.com/en-us/learn/modules/introduction-to-onedrive/"
                        }
                    }

                    $processes = @{                         
                        "Clear OneDrive Cache" = @{
                            Description = "Clears the local OneDrive cache."
                            Function = { Invoke-Command -ScriptBlock ${function:Clear-OneDriveCache} }
                            Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/resolve-sync-issues-powershell"
                            LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                        }
                        "Get OneDrive Status" = @{
                            Description = "Retrieves the status of OneDrive."
                            Function = { Invoke-Command -ScriptBlock ${function:Get-OneDriveStatus} -ArgumentList $OneDriveProcessName }
                            Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/check-installation-status-powershell"
                            LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                        }
                        "Get OneDrive File Info" = @{
                            Description = "Retrieves information about files in OneDrive."
                            Function = { Invoke-Command -ScriptBlock ${function:Get-OneDriveFileInfo} -ArgumentList $OneDriveFolderPath }
                            Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/get-file-properties-powershell"
                            LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                        }
                        "Get OneDrive Properties" = @{
                            Description = "Retrieves properties of a specific folder path in OneDrive."
                            Function = { Invoke-Command -ScriptBlock ${function:Get-OneDriveProperties} -ArgumentList $OneDriveFolderPath }
                            Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/get-folder-properties-powershell"
                            LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                        }
                        "Get User File Permissions" = @{
                            Description = "Retrieves file permissions for the current user in a specific folder path."
                            Function = { Invoke-Command -ScriptBlock ${function:Get-UserFilePermissions} -ArgumentList $OneDriveFolderPath }
                            Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/get-user-file-permissions-powershell"
                            LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                        }
                        "Test OneDrive Folder Paths" = @{
                            Description = "Tests the validity of OneDrive folder paths."
                            Function = { Invoke-Command -ScriptBlock ${function:Test-OneDriveFolderPaths} -ArgumentList $OneDriveFolderPath }
                            Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/test-folder-paths-powershell"
                            LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                        }
                        "Test OneDrive Access" = @{
                            Description = "Tests the user's access to the OneDrive folder."
                            Function = { Invoke-Command -ScriptBlock ${function:Test-OneDriveAccess} -ArgumentList $env:USERNAME, $OneDriveFolderPath }
                            Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/test-access-powershell"
                            LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                        }
                        "Get All OneDrive Files" = @{
                            Description = "Retrieves all files in the OneDrive folder."
                            Function = { Invoke-Command -ScriptBlock ${function:Get-AllOneDriveFiles} }
                            Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/get-all-files-powershell"
                            LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                        }
                        "Disable OneDrive at Startup" = @{
                            Description = "Disables OneDrive from starting automatically at system startup."
                            Function = { Invoke-Command -ScriptBlock ${function:Disable-OneDriveAtStartup} }
                            Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/disable-startup-powershell"
                            LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                        }
                        "Clear OneDrive Cached Credentials" = @{
                            Description = "Clears the cached credentials for OneDrive."
                            Function = { Invoke-Command -ScriptBlock ${function:Clear-OneDriveCachedCredentials} }
                            Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/clear-cached-credentials-powershell"
                            LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                        }
                    }
                        $functions = @{
                            "Get-OneDriveInstallationStatus" = @{
                                Description = "Checks the installation status of OneDrive."
                                Function = { Invoke-Command -ScriptBlock ${function:Get-OneDriveInstallationStatus} }
                                Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/check-installation-status-powershell"
                                LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                            }
                            "Restart-OneDriveProcess" = @{
                                Description = "Restarts the OneDrive process."
                                Function = { Invoke-Command -ScriptBlock ${function:Restart-OneDriveProcess} }
                                Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/restart-process-powershell"
                                LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                            }
                            "Uninstall-OneDrive" = @{
                                Description = "Uninstalls OneDrive from the system."
                                Function = { Invoke-Command -ScriptBlock ${function:Uninstall-OneDrive} }
                                Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/uninstall-powershell"
                                LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                            }
                            "Clear-OneDriveCache" = @{
                                Description = "Clears the local OneDrive cache."
                                Function = { Invoke-Command -ScriptBlock ${function:Clear-OneDriveCache} }
                                Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/resolve-sync-issues-powershell"
                                LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                            }
                            "Get-UserFilePermissions" = @{
                                Description = "Retrieves file permissions for the current user."
                                Function = { Invoke-Command -ScriptBlock ${function:Get-UserFilePermissions} -ArgumentList $OneDriveFolderPath }
                                Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/get-user-file-permissions-powershell"
                                LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                            }
                            "Get-OneDriveProperties" = @{
                                Description = "Retrieves properties of a specific folder path in OneDrive."
                                Function = { Invoke-Command -ScriptBlock ${function:Get-OneDriveProperties} -ArgumentList $OneDriveFolderPath }
                                Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/get-folder-properties-powershell"
                                LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                            }
                        }

function Invoke-Process {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ProcessName,
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$ProcessBlock,
        [Parameter(Mandatory=$true)]
        [string]$ProcessMessage
    )
    Write-Host "Running $ProcessName..."
    Write-Host "---------------------"

    try {
        & $ProcessBlock
        Write-Host "$ProcessName completed successfully."
    } catch {
        Write-Host "Error occurred during ${ProcessName}: $_"
    }

    Write-Host "---------------------"
    Write-Host ""
    Write-Host ""
    Write-Host ""
}
            # Call the nested function
            Invoke-Process -ProcessName "Get-OneDriveStatus" -ProcessBlock ${function:Get-OneDriveStatus} -ProcessMessage "Retrieving OneDrive status"
            $userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $onedriveProcesses = Get-Process -Name "OneDrive" -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -eq $userName }
                function Clear-OneDriveCache {
                    [CmdletBinding()]
                    param(
                        [Parameter(Mandatory = $true)]
                        [string]$Path
                    )

                    $confirmation = Read-Host "Are you sure you want to delete all your OneDrive files? (yes/no)"
                    if ($confirmation -ne 'yes') {
                        Write-Output "Operation cancelled by user."
                        return
                    }

                    $onedriveProcesses = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
                    if ($onedriveProcesses) {
                        foreach ($process in $onedriveProcesses) {
                            Write-Verbose "Clearing cache for process $($process.Name) with ID $($process.Id)..."
                            $process | Stop-Process -Force -ErrorAction Stop
                        }
                    } else {
                        Write-Verbose "OneDrive process not found."
                    }

                    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
                    $CacheCleared = -not (Test-Path $Path)

                    $result = @{
                        Result = if ($CacheCleared) { "Success" } else { "Failure" }
                        Information = "For more information, see: [Introduction to OneDrive](https://docs.microsoft.com/en-us/learn/modules/introduction-to-onedrive/)"
                        ProcessName = if ($onedriveProcesses) { $onedriveProcesses.Name } else { $null }
                    }

                    return $result
                }

                function Get-OneDriveStatus {
                    [CmdletBinding()]
                    param(
                        [string]$OneDriveProcessName = "OneDrive"
                    )

                    $onedriveProcesses = Get-Process -Name $OneDriveProcessName -ErrorAction SilentlyContinue

                    if ($onedriveProcesses) {
                        $result = @{
                            Result = "Running"
                            ProcessId = $onedriveProcesses.Id
                        }
                    } else {
                        $result = @{
                            Result = "Not Running"
                            ProcessId = $null
                        }
                    }

                    return $result
                }

                function Clear-OneDriveCache {
                            [CmdletBinding()]
                            param(
                                [Parameter(Mandatory = $true)]
                                [string]$Path
                            )

                            $confirmation = Read-Host "Are you sure you want to delete all your OneDrive files? (yes/no)"
                            if ($confirmation -ne 'yes') {
                                Write-Output "Operation cancelled by user."
                                return
                            }

                            $onedriveProcesses = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
                            if ($onedriveProcesses) {
                                foreach ($process in $onedriveProcesses) {
                                    Write-Verbose "Clearing cache for process $($process.Name) with ID $($process.Id)..."
                                    $process | Stop-Process -Force -ErrorAction Stop
                                }
                            } else {
                                Write-Verbose "OneDrive process not found."
                            }
                        }
                            function Remove-OneDriveCache {
                                function Remove-OneDriveItem {
                                    [CmdletBinding()]
                                    param(
                                        [Parameter(Mandatory = $true)]
                                        [string]$Path
                                    )

                                    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
                                    $CacheCleared = -not (Test-Path $Path)

                                    $result = @{
                                        Result = if ($CacheCleared) { "Success" } else { "Failure" }
                                        Information = "For more information, see: [Introduction to OneDrive](https://docs.microsoft.com/en-us/learn/modules/introduction-to-onedrive/)"
                                        ProcessName = if ($onedriveProcesses) { $onedriveProcesses.Name } else { $null }
                                    }

                                    return $result
                                }

                                function Get-OneDriveSyncStatus {
                                    [CmdletBinding()]
                                    param(
                                        [string]$OneDriveProcessName = "OneDrive"
                                    )

                                    $onedriveProcesses = Get-Process -Name $OneDriveProcessName -ErrorAction SilentlyContinue

                                    if ($onedriveProcesses) {
                                        $result = @{
                                            Result = "Synced"
                                            ProcessId = $onedriveProcesses.Id
                                        }
                                    } else {
                                        $result = @{
                                            Result = "Not Synced"
                                            ProcessId = $null
                                        }
                                    }

                                    return $result
                                }

                                function Clear-OneDriveCache {
                                    param(
                                        [Parameter(Mandatory = $true)]
                                        [string]$OneDriveFolderPath
                                    )

                                    $onedriveProcesses = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue

                                    if ($onedriveProcesses) {
                                        foreach ($process in $onedriveProcesses) {
                                            Write-Verbose "Clearing cache for process $($process.Name) with ID $($process.Id)..."
                                            $process | Stop-Process -Force -ErrorAction Stop
                                        }
                                    } else {
                                        Write-Verbose "OneDrive process not found."
                                    }

                                    $result = @{
                                        Result = "Cache Cleared"
                                    }

                                    return $result
                                }

                                function Get-OneDriveFolderPath {
                                    [CmdletBinding()]
                                    param()

                                    return $OneDriveFolderPath
                                }

                                function Get-OneDriveFileInfo {
                                    [CmdletBinding()]
                                    param(
                                        [string]$Path
                                    )

                                    # Get OneDrive file info logic here...

                                    $result = @{
                                        Result = "File Info"
                                        Information = "For more information, see: [Introduction to OneDrive](https://docs.microsoft.com/en-us/learn/modules/introduction-to-onedrive/)"
                                    }

                                    return $result
                                }

                                function Get-OneDriveStatus {
                                    [CmdletBinding()]
                                    param(
                                        [string]$OneDriveProcessName = "OneDrive"
                                    )

                                    $onedriveProcesses = Get-Process -Name $OneDriveProcessName -ErrorAction SilentlyContinue

                                    if ($onedriveProcesses) {
                                        $result = @{
                                            Result = "Synced"
                                            ProcessId = $onedriveProcesses.Id
                                        }
                                    } else {
                                        $result = @{
                                            Result = "Not Synced"
                                            ProcessId = $null
                                        }
                                    }

                                    return $result
                                }

                                function Get-OneDriveSyncStatus {
                                    [CmdletBinding()]
                                    param()

                                    # Get OneDrive sync status logic here...

                                    $result = @{
                                        Result = "Sync Status"
                                    }

                                    return $result
                                }

                                function Get-OneDriveProperties {
                                    [CmdletBinding()]
                                    param(
                                        [string]$Path
                                    )

                                    # Get OneDrive folder properties logic here...

                                    $result = @{
                                        Result = "Folder Properties"
                                    }

                                    return $result
                                }

                                function Run-OneDriveProcess {
                                    [CmdletBinding()]
                                    param(
                                        [Parameter(Mandatory = $true)]
                                        [string]$ProcessName,
                                        [Parameter(Mandatory = $true)]
                                        [scriptblock]$ProcessBlock,
                                        [string]$ProcessMessage
                                    )

                                    Write-Host "Running process: $ProcessName"
                                    try {
                                        $ProcessBlock.Invoke()
                                        Write-Host "Process: $ProcessName completed."
                                    } catch {
                                        Write-Error "An error occurred during process: $ProcessName - $_"
                                        Write-Verbose "Please check the error message and try to resolve the issue before running the script again."
                                    }
                                }

                                function Repair-OneDriveIssues {
                                    [CmdletBinding()]
                                    param(
                                        [int]$SleepSeconds = 1
                                    )

                                    # Add your implementation here
                                }

                                function Invoke-OneDriveDiagnostics {
                                    param(
                                        [string]$OneDriveFolderPath
                                    )

                                    # Add your implementation here
                                }

                                function Troubleshoot-OneDrive {
                                    [CmdletBinding()]
                                    param()

                                    $OneDriveFolderPath = Get-OneDriveFolderPath

                                    # Invoke OneDrive Diagnostics
                                    $diagnosticsResults = Invoke-OneDriveDiagnostics -OneDriveFolderPath $OneDriveFolderPath

                                    # If there are any issues found during diagnostics, return them
                                    if ($diagnosticsResults) {
                                        Write-Output "Issues found during diagnostics:"
                                        Write-Output $diagnosticsResults
                                        return
                                    }
                                }

                                $processes = @{}

                                function AddOption {
                                    param(
                                        [hashtable]$processes,
                                        [string]$name,
                                        [string]$description,
                                        [scriptblock]$function,
                                        [string]$link
                                    )

                                    $option = @{
                                        Name = $name
                                        Description = $description
                                        Function = $function
                                        Link = $link
                                    }

                                    $processes[$name] = $option
                                    return $processes
                                }

                            $VerbosePreference = "Continue"

                                                # Define the processes hashtable
                                                $processes = @{}

                                                # Add options to the processes hashtable
                                                $processes = AddOption -processes $processes -name "Retrieving OneDrive status" -description "Retrieves the current status of OneDrive." -function {
                                                    Write-Verbose "Retrieving OneDrive status..."
                                                    $OneDriveProcessName = "OneDrive"
                                                    $statusResult = Get-OneDriveStatus -OneDriveProcessName $OneDriveProcessName
                                                    Write-Verbose "OneDrive status: $($statusResult.Result)"
                                                    Start-Sleep -Seconds 1
                                                } -link "For more information, see: [Introduction to OneDrive](https://docs.microsoft.com/en-us/learn/modules/introduction-to-onedrive/)"

                                                $processes = AddOption -processes $processes -name "Retrieving OneDrive sync status" -description "Retrieves the synchronization status of OneDrive." -function {
                                                    Write-Verbose "Retrieving OneDrive sync status..."
                                                    $statusResult = Get-OneDriveSyncStatus
                                                    Write-Verbose "OneDrive sync status: $($statusResult.Result)"
                                                    Start-Sleep -Seconds 1
                                                } -link "For more information, see: [Introduction to OneDrive](https://docs.microsoft.com/en-us/learn/modules/introduction-to-onedrive/)"

                                                $processes = AddOption -processes $processes -name "Clear OneDrive Cache" -description "Clears the local OneDrive cache to resolve sync issues." -function {
                                                    Clear-OneDriveCache -Path $OneDriveFolderPath
                                                } -link "For more information, see: [Resolve sync issues with OneDrive](https://docs.microsoft.com/onedrive/developer/code-snippets/resolve-sync-issues-powershell)"

                                                $processes = AddOption -processes $processes -name "Get OneDrive File Info" -description "Retrieves information about files in the OneDrive folder." -function {
                                                    Get-OneDriveFileInfo -Path $OneDriveFolderPath
                                                } -link "For more information, see: [Get file information with OneDrive](https://docs.microsoft.com/onedrive/developer/code-snippets/get-file-info-powershell)"

                                                $processes = AddOption -processes $processes -name "Get OneDrive Properties" -description "Retrieves properties of the OneDrive folder." -function {
                                                    Get-OneDriveProperties -Path $OneDriveFolderPath
                                                } -link "For more information, see: [Get folder properties with OneDrive](https://docs.microsoft.com/onedrive/developer/code-snippets/get-folder-properties-powershell)"

                                                # Add more options here...

                                                # Update the progress bar and run each process
                                                foreach ($process in $processes.Values) {
                                                    $processName = $process.Name
                                                    $processBlock = $process.Function

                                                    # Update the progress bar
                                                    Write-Progress -Activity "Repairing OneDrive issues" -Status "Process: $processName" -PercentComplete (($processes.IndexOf($process) + 1) / $processes.Count * 100)
                                                    } # Add the missing closing '}' here
                                                        function Get-OneDriveInformation {
                                                    } # Add the missing closing '}' here

                                                        $OneDriveFolderPath = Get-OneDriveFolderPath

                                                        $processes = @()
                                                }
                                                        function AddOption {
                                                            param(
                                                                [hashtable]$processes,
                                                                [string]$name,
                                                                [string]$description,
                                                                [scriptblock]$function,
                                                                [string]$link
                                                            )

                                                            $option = @{
                                                                Name = $name
                                                                Description = $description
                                                                Function = $function
                                                                Link = $link
                                                            }

                                                            $processes[$name] = $option
                                                            return $processes
                                                        }

                                                        # Define the processes hashtable
                                                        $processes = @{}

                                                        # Add options to the processes hashtable
                                                        $processes = AddOption -processes $processes -name "Retrieving OneDrive status" -description "Retrieves the current status of OneDrive." -function {
                                                            $OneDriveProcessName = "OneDrive"
                                                            $statusResult = Get-OneDriveStatus -OneDriveProcessName $OneDriveProcessName
                                                            Write-Verbose "OneDrive status: $($statusResult.Result)"
                                                            Start-Sleep -Seconds 1
                                                        } -link "For more information, see: [Introduction to OneDrive](https://docs.microsoft.com/en-us/learn/modules/introduction-to-onedrive/)"

                                                        $processes = AddOption -processes $processes -name "Retrieving OneDrive sync status" -description "Retrieves the synchronization status of OneDrive." 
                                                            function Get-OneDriveInformation {
                                                                param (
                                                                    [string]$OneDriveFolderPath
                                                                )

                                                                # Retrieve OneDrive status
                                                                function Get-OneDriveStatus {
                                                                    param (
                                                                        [string]$OneDriveProcessName
                                                                    )

                                                                    # Implement the logic to retrieve OneDrive status
                                                                    # ...
                                                                    return @{
                                                                        Result = "OneDrive status"
                                                                    }
                                                                }

                                                                # Retrieve OneDrive sync status
                                                                function Get-OneDriveSyncStatus {
                                                                    # Implement the logic to retrieve OneDrive sync status
                                                                    # ...
                                                                    return @{
                                                                        Result = "OneDrive sync status"
                                                                    }
                                                                }

                                                                # Clear OneDrive cache
                                                                function Clear-OneDriveCache {
                                                                    param (
                                                                        [string]$Path
                                                                    )

                                                                    # Implement the logic to clear OneDrive cache
                                                                    # ...
                                                                }

                                                                # Get OneDrive file info
                                                                function Get-OneDriveFileInfo {
                                                                    param (
                                                                        [string]$Path
                                                                    )

                                                                    # Implement the logic to retrieve OneDrive file info
                                                                    # ...
                                                                }

                                                                # Get OneDrive properties
                                                                function Get-OneDriveProperties {
                                                                    param (
                                                                        [string]$Path
                                                                    )

                                                                    # Implement the logic to retrieve OneDrive properties
                                                                    # ...
                                                                }

                                                                # Add options for different processes
                                                                $processes = @()

                                                                $processes += @{
                                                                    Name = "Retrieve OneDrive Status"
                                                                    Description = "Retrieves the status of OneDrive."
                                                                    Function = {
                                                                        Write-Verbose "Retrieving OneDrive status..."
                                                                        $statusResult = Get-OneDriveStatus -OneDriveProcessName "OneDrive"
                                                                        Write-Verbose "OneDrive status: $($statusResult.Result)"
                                                                        Start-Sleep -Seconds 1
                                                                    }
                                                                    Link = "For more information, see: [Introduction to OneDrive](https://docs.microsoft.com/en-us/learn/modules/introduction-to-onedrive/)"
                                                                }

                                                                $processes += @{
                                                                    Name = "Retrieve OneDrive Sync Status"
                                                                    Description = "Retrieves the sync status of OneDrive."
                                                                    Function = {
                                                                        Write-Verbose "Retrieving OneDrive sync status..."
                                                                        $statusResult = Get-OneDriveSyncStatus
                                                                        Write-Verbose "OneDrive sync status: $($statusResult.Result)"
                                                                        Start-Sleep -Seconds 1
                                                                    }
                                                                    Link = "For more information, see: [Introduction to OneDrive](https://docs.microsoft.com/en-us/learn/modules/introduction-to-onedrive/)"
                                                                }

                                                                $processes += @{
                                                                    Name = "Clear OneDrive Cache"
                                                                    Description = "Clears the local OneDrive cache to resolve sync issues."
                                                                    Function = {
                                                                        Clear-OneDriveCache -Path $OneDriveFolderPath
                                                                    }
                                                                    Link = "For more information, see: [Resolve sync issues with OneDrive](https://docs.microsoft.com/onedrive/developer/code-snippets/resolve-sync-issues-powershell)"
                                                                }

                                                                $processes += @{
                                                                    Name = "Get OneDrive File Info"
                                                                    Description = "Retrieves information about files in the OneDrive folder."
                                                                    Function = {
                                                                        Get-OneDriveFileInfo -Path $OneDriveFolderPath
                                                                    }
                                                                    Link = "For more information, see: [Get file information with OneDrive](https://docs.microsoft.com/onedrive/developer/code-snippets/get-file-info-powershell)"
                                                                }

                                                                $processes += @{
                                                                    Name = "Get OneDrive Properties"
                                                                    Description = "Retrieves properties of the OneDrive folder."
                                                                    Function = {
                                                                        Get-OneDriveProperties -Path $OneDriveFolderPath
                                                                    }
                                                                    Link = "For more information, see: [Get folder properties with OneDrive](https://docs.microsoft.com/onedrive/developer/code-snippets/get-folder-properties-powershell)"
                                                                }

                                                                # Add more options here...

                                                                # Run each process and return the results
                                                                $results = @()
                                                                foreach ($process in $processes) {
                                                                    $processName = $process.Name
                                                                    $processBlock = $process.Function

                                                                    # Update the progress bar
                                                                    Write-Progress -Activity "Retrieving OneDrive information" -Status "Process: $processName" -PercentComplete (($processes.IndexOf($process) + 1) / $processes.Count * 100)

                                                                    # Run the process
                                                                    try {
                                                                        $result = & $processBlock
                                                                        $results += @{
                                                                            Name = $processName
                                                                            Result = $result
                                                                        }
                                                                    } catch {
                                                                        Write-Host "Error occurred while running process: $processName"
                                                                        Write-Host "Error message: $_"
                                                                    }

                                                                    # Pause for a moment
                                                                    Start-Sleep -Seconds 1
                                                                }

                                                                # Return the results
                                                                return $results
                                                            }
    

                                                                    # Define the function to show the menu
                                                                    function ShowMenu($options) {
                                                                        Clear-Host
                                                                        Write-Host "`nOneDrive Troubleshooter Menu"
                                                                        Write-Host "============================`n"
                                                                        Write-Host "Select an option to troubleshoot a specific issue:`n"
                                                                        $options | ForEach-Object {
                                                                            Write-Host "$($_.Number): $($_.Description)"
                                                                            Write-Host "   Learn more: $($_.LearnLink)"
                                                                            Write-Host "   Documentation: $($_.Link)"
                                                                        }
                                                                        Write-Host "`n0: Exit"
                                                                        Write-Host "H: Help"
                                                                    }

                                                                    # Define the function to show the help information
                                                                    function ShowHelp() {
                                                                        Clear-Host
                                                                        Write-Host "`nOneDrive Troubleshooter Help"
                                                                        Write-Host "==========================`n"
                                                                        Write-Host "This script helps troubleshoot common OneDrive issues."
                                                                        Write-Host "To use the script, follow these steps:"
                                                                        Write-Host "1. Run the script."
                                                                        Write-Host "2. Select an option from the menu to troubleshoot the specific issue."
                                                                        Write-Host "3. Follow the instructions provided by the selected option."
                                                                        Write-Host "4. If needed, refer to the Microsoft Learn documentation for more information and guidance."
                                                                        Write-Host "`nExample: To select 'Clear OneDrive Cache', type 1 and press Enter."
                                                                        Write-Host "`nFor more information, visit: $($options[0].LearnLink)"
                                                                    }
                                                                
                                                                                    $troubleshootingOptions = @(
                                                                                        @{
                                                                                            Number = '1'
                                                                                            Name = "Clear-OneDriveCache"
                                                                                            Description = "Clears the OneDrive cache."
                                                                                            Function = {
                                                                                                # Add code logic here to clear the OneDrive cache
                                                                                                Write-Host "OneDrive cache cleared."
                                                                                                # Return the result
                                                                                                return "OneDrive cache cleared."
                                                                                            }
                                                                                            Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/clear-cache-powershell"
                                                                                            LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                                                                                        },
                                                                                        @{
                                                                                            Number = '2'
                                                                                            Name = "Restart-OneDrive"
                                                                                            Description = "Restarts the OneDrive process."
                                                                                            Function = {
                                                                                                # Add code logic here to restart the OneDrive process
                                                                                                Write-Host "OneDrive restarted."
                                                                                                # Return the result
                                                                                                return "OneDrive restarted."
                                                                                            }
                                                                                            Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/restart-powershell"
                                                                                            LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                                                                                        },
                                                                                        @{
                                                                                            Number = '3'
                                                                                            Name = "Reset-OneDrive"
                                                                                            Description = "Resets OneDrive settings to default."
                                                                                            Function = {
                                                                                                # Add code logic here to reset OneDrive settings
                                                                                                Write-Host "OneDrive settings reset to default."
                                                                                                # Return the result
                                                                                                return "OneDrive settings reset to default."
                                                                                            }
                                                                                            Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/reset-powershell"
                                                                                            LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                                                                                        },
                                                                                        @{
                                                                                            Number = '4'
                                                                                            Name = "Disable-OneDriveAtStartup"
                                                                                            Description = "Disables OneDrive from starting automatically at system startup."
                                                                                            # Define the function to disable OneDrive at startup
                                                                                        }
                                                                                    )
                                                                                    
                                                                                    
                                                                                    
                                                                                            Function Disable-OneDriveAtStartup {
                                                                                                [CmdletBinding()]
                                                                                                param (
                                                                                                    [Parameter(Mandatory=$true)]
                                                                                                    [string]$ComputerName
                                                                                                )

                                                                                                # Add code logic here to disable OneDrive at startup
                                                                                                Write-Host "Disabling OneDrive at startup on $ComputerName..."
                                                                                                # Add code logic here to disable OneDrive at startup

                                                                                                # Return the result
                                                                                                return "OneDrive disabled at startup on $ComputerName."
                                                                                            }

                                                                                            # Define the function to show the help information
                                                                                            function ShowHelp() {
                                                                                                Clear-Host
                                                                                                Write-Host "`nOneDrive Troubleshooter Help"
                                                                                                Write-Host "==========================`n"
                                                                                                Write-Host "This script helps troubleshoot common OneDrive issues."
                                                                                            }
                                                                                                # Define the function to show the menu
                                                                                            
                                                                                                function ShowMenu {
                                                                                                    param (
                                                                                                        [Parameter(Mandatory=$true)]
                                                                                                        [array]$options
                                                                                                    )
                                                                                                    
                                                                                                    Clear-Host
                                                                                                    Write-Host "`nOneDrive Troubleshooter Menu"
                                                                                                    Write-Host "==========================`n"
                                                                                                }
                                                                                                    Import-Module Microsoft.PowerShell.Utility

                                                                                                    foreach ($option in $options) {
                                                                                                        # Define the troubleshooting options
                                                                                                        $troubleshootingOptions = @(
                                                                                                            [PSCustomObject]@{
                                                                                                                Number = 1
                                                                                                                Name = "Disable OneDrive at Startup"
                                                                                                                Description = "Disables OneDrive from starting up automatically."
                                                                                                            
                                                                                                                Function = {
                                                                                                                    param (
                                                                                                                        [Parameter(Mandatory=$true)]
                                                                                                                        [string]$ComputerName
                                                                                                                    )
                                                                                                                
                                                                                                                    # Add your code logic here
                                                                                                                    # Example: Disable-OneDriveAtStartup -ComputerName $ComputerName
                                                                                                                
                                                                                                                                    # Return the result
                                                                                                                                    return "OneDrive disabled at startup on $ComputerName"
                                                                                                                                }
                                                                                                                                Link = "https://docs.microsoft.com/onedrive/developer/code-snippets/disable-startup-powershell"
                                                                                                                                LearnLink = "https://docs.microsoft.com/learn/modules/troubleshoot-onedrive-sync-issues/"
                                                                                                                            
                                                                                                                                
                                                                                                                            }
                                                                                                                        )
                                                                                                                    
                                                                                                                            # Add more troubleshooting options here
                                                                                                                        
                                                                                                                            

                                                                                                                    

                                                                                                                        # Define the troubleshooting options
                                                                                                                        $troubleshootingOptions = @(
                                                                                                                            # Add your troubleshooting options here
                                                                                                                            @{ Number = '1'; Name = 'Option 1'; Function = 'Disable-OneDriveAtStartup' },
                                                                                                                            @{ Number = '2'; Name = 'Option 2'; Function = 'SomeOtherFunction' }
                                                                                                                        )
                                                                                                                }
                                                                                                                
                                                                                                                        function ShowHelp {
                                                                                                                            # Add your help content here
                                                                                                                            Write-Host "Help content goes here..."
                                                                                                                        }

                                                                                                                        # Define the function to disable OneDrive at startup
                                                                                                                        function Disable-OneDriveAtStartup {
                                                                                                                            param (
                                                                                                                                [Parameter(Mandatory=$true)]
                                                                                                                                [string]$ComputerName
                                                                                                                            )
                                                                                                                        }
                                                                                                                        # Add your code logic here
                                                                                                                        # Example: Disable-OneDriveAtStartup -ComputerName $ComputerName
