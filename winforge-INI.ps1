<#
    .SYNOPSIS
    This script automates the configuration of a Windows system using parameters specified in an INI file.

    .PARAMETER config
    The path to the configuration file. This can be a local path or a URL to an INI file containing the necessary configuration parameters.

    .DESCRIPTION
    This script performs a series of system configurations based on the values specified in the provided INI file. 
    The configurations include setting the computer name, locale, timezone, installing applications, setting wallpapers and lock screens, 
    modifying registry entries, configuring network settings, power settings, software updates, security settings, environment variables, 
    importing tasks into Task Scheduler, installing Google Chrome Enterprise, Google Credential Provider for Windows (GCPW), Google Drive, and activating Windows.

    .EXAMPLE
    .\install.ps1 -config="C:\Path\To\Config.ini"

    .EXAMPLE
    .\install.ps1 -config="https://www.github.com/Acme/Winforge/config.ini"
    .\install.ps1 -config="https://drive.google.com/uc?export=download&id=1-92-Zs5q_v1Azxed0OY0VfxRHXPe4Xp1"

    Ensure that the script is run with administrative privileges to apply the configurations successfully.

#>

# Define paths and initialize variables
param (
    [Parameter(Mandatory=$true)]
    [string]$configFile
)

$logFile = Join-Path -Path $env:SYSTEMDRIVE -ChildPath "winforge-configuration.log"
$config = @{}

$ProgressPreference = 'SilentlyContinue'

# Function to check if the current user is an admin
function Test-IsAdmin {
    $admin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544')
    return $admin
}

# Download and read the configuration file if it's a URL
function Get-ConfigFile {
    param (
        [string]$configFile
    )
    if ($configFile -match "^https?://") {
        $tempConfigFile = "$env:TEMP\config.ini"
        Write-Log "Downloading configuration file from: $configFile"
        Invoke-WebRequest -Uri $configFile -OutFile $tempConfigFile
        $configFile = $tempConfigFile
    }
    return $configFile
}

# Function to read INI file
function Read-ConfigFile {
    param (
        [string]$path
    )
    $ini = @{}
    $section = ""
    Get-Content $path | ForEach-Object {
        $_ = $_.Trim()
        if ($_ -match '^\[(.+)\]$') {
            $section = $matches[1].Trim()
            $ini[$section] = @{}
        } elseif ($_ -match '^(.*)=(.*)$') {
            $name, $value = $matches[1].Trim(), $matches[2].Trim()
            $value = $value.Trim('"')  # Remove surrounding quotes
            $ini[$section][$name] = $value
        }
    }
    return $ini
}

# Function to get configuration value by key and section
function Get-ConfigValue {
    param (
        [string]$section,
        [string]$key
    )
    if ($config[$section] -and $config[$section][$key]) {
        return $config[$section][$key]
    } else {
        return $null
    }
}

# Function to validate required keys for sections
function Validate-RequiredKeys {
    param (
        [string]$section,
        [string[]]$requiredKeys
    )
    foreach ($key in $requiredKeys) {
        if (-not $config[$section][$key]) {
            Write-Log "Missing required key '$key' in section '$section'"
            return $false
        }
    }
    return $true
}

# Function to log messages
function Write-Log {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Write-Output $logMessage | Out-File -Append -FilePath $logFile
}

# Functions to output the script activity to the user
function Write-SystemMessage {
    param (
        [Parameter()]
        [string] $title = '',
  
        [Parameter()]
        [string] $msg1 = '',

        [Parameter()]
        [string] $msg2 = '',
  
        [Parameter()]
        $titleColor = 'DarkMagenta',
  
        [Parameter()]
        $msg1Color = 'Cyan',

        [Parameter()]
        $msg2color = 'White'
    )
    
    
    if ($PSBoundParameters.ContainsKey('title')) {
        Write-Host
        Write-Host " $title ".ToUpper() -ForegroundColor White -BackgroundColor $titleColor 
        Write-Host
    }
  
    if ($PSBoundParameters.ContainsKey('msg1') -and $PSBoundParameters.ContainsKey('msg2')){
        Write-Host "$msg1" -ForegroundColor $msg1Color -NoNewline; Write-Host "$msg2" -ForegroundColor $msg2color
        return
    }

    if ($PSBoundParameters.ContainsKey('msg1')) {
        Write-Host "$msg1" -ForegroundColor $msg1Color
    }

    if ($PSBoundParameters.ContainsKey('msg2')) {
        Write-Host "$msg2" -ForegroundColor $msg2color
    }

}

function Write-ErrorMessage {
    param (
      [Parameter()]
      $msg = "CRITICAL ERROR",
  
      [Parameter()]
      $color = 'White'
    )
  
    Write-Host
    Write-Host " $msg ".ToUpper() -ForegroundColor $color -BackgroundColor DarkRed
    Write-Host
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host
  }

function Write-SuccessMessage {
    param (
      [Parameter()]
      $msg = "Success",
  
      [Parameter()]
      $msgColor = 'Green'
    )
  
    Write-Host
    Write-Host "Success: $msg " -ForegroundColor $msgColor -BackgroundColor Black
    Write-Host
  }

# Function to add, modify, or remove registry settings.
function RegistryTouch {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("add", "remove")]
        [string]$action,

        [Parameter(Mandatory = $true)]
        [string]$path,

        [Parameter(Mandatory = $true)]
        [string]$name,

        [Parameter()]
        [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "QWord")]
        [string]$type = "String",  # Default to String

        [Parameter()]
        [object]$value  # Changed to object to handle various data types
    )

    try {
        # Detect the base registry hive
        switch -regex ($path) {
            '^HKLM:\\|^HKEY_LOCAL_MACHINE\\' {
                $baseKey = "HKLM:"
                $pathWithoutHive = $path -replace '^HKLM:\\|^HKEY_LOCAL_MACHINE\\', ''
            }
            '^HKCU:\\|^HKEY_CURRENT_USER\\' {
                $baseKey = "HKCU:"
                $pathWithoutHive = $path -replace '^HKCU:\\|^HKEY_CURRENT_USER\\', ''
            }
            '^HKCR:\\|^HKEY_CLASSES_ROOT\\' {
                $baseKey = "HKCR:"
                $pathWithoutHive = $path -replace '^HKCR:\\|^HKEY_CLASSES_ROOT\\', ''
            }
            '^HKU:\\|^HKEY_USERS\\' {
                $baseKey = "HKU:"
                $pathWithoutHive = $path -replace '^HKU:\\|^HKEY_USERS\\', ''
            }
            '^HKCC:\\|^HKEY_CURRENT_CONFIG\\' {
                $baseKey = "HKCC:"
                $pathWithoutHive = $path -replace '^HKCC:\\|^HKEY_CURRENT_CONFIG\\', ''
            }
            default {
                Write-Log "Unsupported registry hive in path: $path"
                Write-ErrorMessage -msg "Unsupported registry hive."
                return
            }
        }

        # Build the full registry path
        $fullKeyPath = $baseKey
        $subKeyParts = $pathWithoutHive -split "\\"

        # Incrementally create any missing registry keys
        foreach ($part in $subKeyParts) {
            $fullKeyPath = Join-Path $fullKeyPath $part
            if (-not (Test-Path $fullKeyPath)) {
                Write-Log "Creating missing registry key: $fullKeyPath"
                New-Item -Path $fullKeyPath -Force -ErrorAction Stop | Out-Null
            }
        }

        # Now that all parent keys exist, handle the registry value
        if ($action -eq "add") {
            $itemExists = Get-ItemProperty -Path $fullKeyPath -Name $name -ErrorAction SilentlyContinue

            if (-not $itemExists) {
                Write-Log "Registry item does not exist. Creating item: $name with value: $value"
                New-ItemProperty -Path $fullKeyPath -Name $name -Value $value -PropertyType $type -Force -ErrorAction Stop | Out-Null
            } else {
                # Retrieve the current value with proper data type handling
                $currentValue = (Get-ItemProperty -Path $fullKeyPath -Name $name).$name

                # Convert current value and new value to the appropriate types for comparison
                switch ($type) {
                    "DWord" {
                        $currentValue = [int]$currentValue
                        $value = [int]$value
                    }
                    "QWord" {
                        $currentValue = [long]$currentValue
                        $value = [long]$value
                    }
                    "Binary" {
                        $currentValue = [Byte[]]$currentValue
                        $value = [Byte[]]$value
                    }
                    default {
                        $currentValue = [string]$currentValue
                        $value = [string]$value
                    }
                }

                if (-not ($currentValue -eq $value)) {
                    Write-Log "Registry value differs. Updating item: $name from $currentValue to $value"
                    Set-ItemProperty -Path $fullKeyPath -Name $name -Value $value -Force -ErrorAction Stop
                } else {
                    Write-Log "Registry item: $name with value: $value already exists. Skipping."
                }
            }
        } elseif ($action -eq "remove") {
            # Check if the registry value exists
            if (Get-ItemProperty -Path $fullKeyPath -Name $name -ErrorAction SilentlyContinue) {
                Write-Log "Removing registry item: $name from path: $fullKeyPath"
                Remove-ItemProperty -Path $fullKeyPath -Name $name -Force -ErrorAction Stop
            } else {
                Write-Log "Registry item: $name does not exist at path: $fullKeyPath. Skipping."
            }
        }
    } catch {
        Write-Log "Error modifying the registry: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error modifying the registry: $($_.Exception.Message)"
    }
}

function Set-SystemCheckpoint {
    $date = Get-Date -Format "dd/MM/yyyy"
    $snapshotName = "Winforge - $date"
  
    try {
        Write-Log "Creating system restore point. Snapshot Name: $snapshotName"
        Write-SystemMessage -title "Creating System Restore Point" -msg1 "Snapshot Name: " -msg2 $snapshotName
        
        # Ensure system restore is enabled on the system drive
        Enable-ComputerRestore -Drive "$env:systemdrive"
        
        # Create the system restore point
        Checkpoint-Computer -Description $snapshotName -RestorePointType "MODIFY_SETTINGS" -Verbose
        
        Write-Log "System restore point created successfully."
        Write-SuccessMessage -msg "System restore point created successfully."

    } catch {
        Write-Log "Error creating system restore point: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to create system restore point: $($_.Exception.Message)"
        Return
    }
}

# Function to set computer name
function Set-ComputerName {

    try {
        $computerName = Get-ConfigValue -section "System" -key "ComputerName"
        
        if ($computerName) {
            Write-Log "Setting computer name to: $computerName"
            Rename-Computer -NewName $computerName -Force
            Write-Log "Computer name set successfully."
        } else {
            Write-Log "Computer name not set. Missing configuration."
        }
    } catch {
        Write-Log "Error setting computer name: $($_.Exception.Message)"
        Return
    }
}

# Function to set locale
function Set-Locale {
    try {
        $locale = Get-ConfigValue -section "System" -key "Locale"
        if ($locale) {
            Write-Log "Setting locale to: $locale"
            # Validate the locale against a list of supported locales if necessary
            if (Get-WinUserLanguageList | Where-Object { $_.LanguageTag -eq $locale }) {
                Set-WinUILanguageOverride -Language $locale
                Set-WinSystemLocale -SystemLocale $locale
                Set-WinUserLanguageList $locale -Force
                Write-Log "Locale set successfully."
            } else {
                Write-Log "Invalid or unsupported locale: $locale"
            }
        } else {
            Write-Log "Locale not set. Missing configuration."
        }
    } catch {
        Write-Log "Error setting locale: $($_.Exception.Message)"
        Return
    }
}

# Function to set timezone
function Set-SystemTimezone {
    try {
        $timezone = Get-ConfigValue -section "System" -key "Timezone"
        if ($timezone) {
            $currentTZ = (Get-TimeZone).Id
            if ($currentTZ -ne $timezone) {
                Write-Log "Setting timezone to: $timezone"
                Set-TimeZone -Id $timezone
                $currentTZ = (Get-TimeZone).Id
                if ($currentTZ -eq $timezone) {
                    Write-Log "Timezone set successfully to: $timezone"
                } else {
                    Write-Log "Failed to set timezone to: $timezone"
                }
            } else {
                Write-Log "Timezone is already set to: $timezone"
            }
        } else {
            Write-Log "Timezone not set. Missing configuration."
        }
    } catch {
        Write-Log "Error setting timezone: $($_.Exception.Message)"
        Return
    }
}

# Function to disable OneDrive
function Set-DisableOneDrive {
    try {
        $disableOneDrive = Get-ConfigValue -section "System" -key "DisableOneDrive"
        
        if ($disableOneDrive -eq "TRUE") {
            Write-Log "Disabling OneDrive."
            Write-SystemMessage -msg1 "- Disabling OneDrive."
            try {
                # Use RegistryTouch to disable OneDrive
                RegistryTouch -action add -path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" -name "DisableFileSyncNGSC" -type "DWord" -value 1
                
                # Stop OneDrive process
                Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
                
                Write-SuccessMessage -msg "OneDrive disabled."
                Write-Log "OneDrive disabled successfully."
            } catch {
                Write-Log "Error disabling OneDrive: $($_.Exception.Message)"
                Write-ErrorMessage -msg "Failed to disable OneDrive."
            }
        } elseif ($disableOneDrive -eq "FALSE") {
            Write-Log "Enable OneDrive selected, skipping OneDrive disable."
            Write-SystemMessage -msg1 "- OneDrive remains enabled."
        } else {
            Write-Log "Disable OneDrive not set or invalid value. Skipping."
        }
    } catch {
        Write-Log "Error in Set-DisableOneDrive function: $($_.Exception.Message)"
        return
    }
}

# Function to disable Windows Copilot
function Set-DisableCopilot {
    try {
        $disableCopilot = Get-ConfigValue -section "System" -key "DisableCopilot"
        
        if ($disableCopilot -eq "TRUE") {
            Write-Log "Disabling Windows Copilot."
            Write-SystemMessage -msg1 "- Disabling Windows Copilot."
            try {
                # Use RegistryTouch to disable Windows Copilot
                RegistryTouch -action add -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -name "CopilotEnabled" -type "DWord" -value 0
                
                Write-SuccessMessage -msg "Windows Copilot disabled."
                Write-Log "Windows Copilot disabled successfully."
            } catch {
                Write-Log "Error disabling Windows Copilot: $($_.Exception.Message)"
                Write-ErrorMessage -msg "Failed to disable Windows Copilot."
            }
        } elseif ($disableCopilot -eq "FALSE") {
            Write-Log "Enable Copilot selected, skipping Copilot disable."
            Write-SystemMessage -msg1 "- Windows Copilot remains enabled."
        } else {
            Write-Log "Disable Copilot not set or invalid value. Skipping."
        }
    } catch {
        Write-Log "Error in Set-DisableCopilot function: $($_.Exception.Message)"
        return
    }
}


# Function to test if a program is installed
function Test-ProgramInstalled {
    param(
        [string]$ProgramName
    )

    $InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                         ForEach-Object { [PSCustomObject]@{ 
                            DisplayName = $_.GetValue('DisplayName')
                            DisplayVersion = $_.GetValue('DisplayVersion')
                        }}

    # Check if the partial program name exists in the filtered list
    $isProgramInstalled = $InstalledSoftware | Where-Object { $_.DisplayName -like "*$ProgramName*" }

    return $isProgramInstalled
}

# Function to install applications via winget using manifest files
function Install-WingetApps {
    $packageManager = Get-ConfigValue -section "Applications" -key "PackageManager"
    
    # Only proceed if Winget is the selected package manager
    if ($packageManager -ne "Winget") {
        Write-Log "Winget is not selected as the package manager. Skipping Winget app installation."
        return
    }

    $appManifestFile = Get-ConfigValue -section "Applications" -key "WingetAppManifest"
    
    if ($appManifestFile) {
        Write-SystemMessage -title "Installing Winget Applications"
        Write-Log "Installing applications via winget import"

        # Download the manifest file if it's a URL
        if ($appManifestFile -match "^https?://") {
            $tempAppManifestFile = "$env:TEMP\appManifest.json"
            Write-Log "Downloading app manifest file from: $appManifestFile"
            Write-SystemMessage -msg1 "- Downloading app manifest file from: " -msg2 $appManifestFile
            
            try {
                Invoke-WebRequest -Uri $appManifestFile -OutFile $tempAppManifestFile
                $appManifestFile = $tempAppManifestFile
            } catch {
                Write-Log "Error downloading app manifest file from: $appManifestFile. Error: $($_.Exception.Message)"
                Write-ErrorMessage -msg "Error downloading app manifest file from: $appManifestFile. Error: $($_.Exception.Message)"
                Return
            }

            Write-SuccessMessage -msg "App manifest downloaded."
        }

        try {
            # Reset Winget sources and accept agreements
            Write-Log "Resetting Winget sources."
            Write-SystemMessage -msg1 "- Resetting Winget sources."
            
            winget source reset --force
            Add-AppxPackage -Path "https://cdn.winget.microsoft.com/cache/source.msix"

            Write-Log "Winget sources reset and agreements accepted successfully."
            Write-SystemMessage -msg1 "- Winget sources reset and agreements accepted successfully." -msg1Color "Green"
        } catch {
            Write-Log "Error resetting Winget sources or accepting agreements: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Error resetting Winget sources or accepting agreements: $($_.Exception.Message)"
            Return
        }

        try {
            Write-Log "Installing applications from manifest file: $appManifestFile"
            Write-SystemMessage -msg1 "- Installing applications from manifest file"
            winget import -i $appManifestFile --accept-package-agreements --ignore-versions --accept-source-agreements
        } catch {
            Write-Log "Error installing applications from manifest file ${appManifestFile}: $($_.Exception.Message)"
            Write-ErrorMessage -msg "- Error installing applications from manifest file ${appManifestFile}: $($_.Exception.Message)"
            Return
        }

        Write-Log "App installation complete."
        Write-SuccessMessage -msg "Applications installed successfully."
        
    } else {
        Write-Log "No app manifest file provided for Winget."
        Write-SystemMessage -msg1 "No app manifest file provided for Winget." -msg1Color "Cyan"
    }
}

# Function to install Chocolatey and Chocolatey Apps
function Install-ChocolateyApps {
    try {
        # Check if ChocolateyApps is configured
        $chocoApps = Get-ConfigValue -section "Applications" -key "ChocolateyApps"
        if ($chocoApps) {
            Write-Log "Detected Chocolatey apps for installation: $chocoApps"

            # Check if Chocolatey is installed, and if not, install it
            if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                Write-SystemMessage -msg1 "Chocolatey not found, installing Chocolatey..."
                Write-Log "Installing Chocolatey..."
                Set-ExecutionPolicy Bypass -Scope Process -Force
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

                if (Get-Command choco -ErrorAction SilentlyContinue) {
                    Write-SystemMessage -msg1 "Chocolatey installed successfully." -msg1Color "Green"
                    Write-Log "Chocolatey installed successfully."
                } else {
                    Write-ErrorMessage -msg "Failed to install Chocolatey."
                    Write-Log "Failed to install Chocolatey."
                    return
                }
            }

            # Split the list of Chocolatey apps and install each one
            $appList = $chocoApps -split ',' | ForEach-Object { $_.Trim() }  # Split by comma and trim whitespace

            foreach ($app in $appList) {
                Write-Log "Installing Chocolatey app: $app"

                # Use double quotes around app name to avoid issues with special characters
                try {
                    Start-Process -NoNewWindow -Wait -FilePath "choco" -ArgumentList "install `"$app`" -y" -ErrorAction Stop
                    Write-Log "$app installed successfully."
                    Write-SystemMessage -msg1 "$app installed successfully." -msg1Color "Green"
                } catch {
                    Write-Log "Error installing ${app}: $($_.Exception.Message)"
                    Write-ErrorMessage -msg "Error installing ${app}: $($_.Exception.Message)"
                }
            }

            Write-Log "All Chocolatey apps installation completed."
            Write-SuccessMessage -msg "Chocolatey apps installed successfully."
        } else {
            Write-Log "No Chocolatey apps provided for installation."
        }
    } catch {
        Write-ErrorMessage -msg "Error in Chocolatey installation process: $($_.Exception.Message)"
        Write-Log "Error in Chocolatey installation process: $($_.Exception.Message)"
        return
    }
}

# Function to test if a font is installed
function Test-FontInstalled {
    param(
        [string]$FontName
    )

    $InstalledFonts = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" |
                      Get-ItemProperty |
                      ForEach-Object { [PSCustomObject]@{ 
                            FontName = $_.PSObject.Properties.Name
                            FontFile = $_.PSObject.Properties.Value
                        }}

    # Check if the partial font name exists in the filtered list
    $isFontInstalled = $InstalledFonts | Where-Object { $_.FontName -like "*$FontName*" }

    return $isFontInstalled
}

# Function to download font files from GitHub
function Get-Fonts {
    param (
        [string]$fontName,
        [string]$outputPath
    )

    $githubUrl = "https://github.com/google/fonts"
    $fontRepoUrl = "$githubUrl/tree/main/ofl/$fontName"

    # Create output directory if it doesn't exist
    if (-not (Test-Path -Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath | Out-Null
    }

    # Fetch font file URLs from GitHub
    $fontFilesPage = Invoke-WebRequest -Uri $fontRepoUrl -UseBasicParsing
    $fontFileLinks = $fontFilesPage.Links | Where-Object { $_.href -match "\.ttf$" -or $_.href -match "\.otf$" }

    foreach ($link in $fontFileLinks) {
        $fileUrl = "https://github.com" + $link.href.Replace("/blob/", "/raw/")
        $fileName = [System.IO.Path]::GetFileName($link.href)

        # Download font file
        Write-Log "Downloading $fileName from: $fileUrl"
        Invoke-WebRequest -Uri $fileUrl -OutFile (Join-Path -Path $outputPath -ChildPath $fileName)
    }

    Write-Log "Download complete. Fonts saved to $outputPath"
}

# Function to install Google fonts from GitHub repository
function Install-Fonts {
    try {
        $fonts = Get-ConfigValue -section "Fonts" -key "Fonts"
        if ($fonts) {
            $fontsList = $fonts -split ',' | ForEach-Object { $_.Trim('"').ToLower() }
            $ProgressPreference = 'SilentlyContinue'
            $tempDownloadFolder = "$env:TEMP\google_fonts"
            Write-SystemMessage -title "Installing Fonts"

            foreach ($fontName in $fontsList) {
                # Correct the font names for the GitHub repository
                $correctFontName = $fontName -replace "\+", ""

                # Check if the font is already installed
                $isFontInstalled = Test-FontInstalled -FontName $correctFontName

                if ($isFontInstalled) {
                    Write-Log "Font $correctFontName is already installed. Skipping download and installation."
                    Write-SystemMessage -msg1 "- $correctFontName is already installed. Skipping installation." -msg1Color "Cyan"
                    continue
                }

                Write-Log "Downloading & Installing $correctFontName from Google Fonts GitHub repository. Please wait..."
                Write-SystemMessage -msg1 "- Downloading & Installing: " -msg2 $correctFontName

                # Download the font files
                Get-Fonts -fontName $correctFontName -outputPath $tempDownloadFolder

                # Install the font files
                $allFonts = Get-ChildItem -Path $tempDownloadFolder -Include *.ttf, *.otf -Recurse
                foreach ($font in $allFonts) {
                    $fontDestination = Join-Path -Path $env:windir\Fonts -ChildPath $font.Name
                    Copy-Item -Path $font.FullName -Destination $fontDestination -Force

                    # Use RegistryTouch to register the font
                    RegistryTouch -action add `
                        -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" `
                        -name $font.BaseName `
                        -value $font.Name `
                        -type "String"
                }

                Write-Log "Font installed: $correctFontName"
                Write-SystemMessage -msg1 "- $correctFontName installed successfully." -msg1Color "Green"

                # Clean up the downloaded font files
                Remove-Item -Path $tempDownloadFolder -Recurse -Force
            }

            Write-Log "All fonts installed successfully."
            Write-SuccessMessage -msg "All fonts installed successfully."
        } else {
            Write-Log "No fonts to install. Missing configuration."
        }
    } catch {
        Write-Log "Error installing fonts: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error installing fonts: $($_.Exception.Message)"
        Return
    }
}


# Function to install Microsoft Office
function Install-Office {

    # Guard clause to check if the "Office" section exists
    if (-not $config.ContainsKey("Office")) {
        Write-Log "Office section not found in the config. Skipping Office settings configuration."
        return
    }
    
    try {
        $officeSectionExists = $config.ContainsKey("Office")
        if ($officeSectionExists) {
            # Check if Office is already installed
            if (Test-ProgramInstalled 'Microsoft Office' -or Test-ProgramInstalled 'Office') {
                Write-Log "Microsoft Office is already installed. Skipping installation."
                Write-SystemMessage -msg1 "Microsoft Office is already installed. Skipping installation." -msg1Color "Cyan"
                return
            }

            Write-SystemMessage -title "Installing Microsoft Office"
            $requiredKeys = @("LicenseKey", "ProductID", "LanguageID", "UpdatesEnabled", "DisplayLevel", "SetupReboot", "Channel", "OfficeClientEdition")
            if (-not (Validate-RequiredKeys -section "Office" -requiredKeys $requiredKeys)) {
                Write-Log "Skipping Office installation due to missing keys."
                Write-SystemMessage -msg1 "Skipping Office installation due to missing keys." -msg1Color "Yellow"
                return
            }

            $licenseKey = Get-ConfigValue -section "Office" -key "LicenseKey"
            $productID = Get-ConfigValue -section "Office" -key "ProductID"
            $languageID = Get-ConfigValue -section "Office" -key "LanguageID"
            $updatesEnabled = Get-ConfigValue -section "Office" -key "UpdatesEnabled"
            $displayLevel = Get-ConfigValue -section "Office" -key "DisplayLevel"
            $setupReboot = Get-ConfigValue -section "Office" -key "SetupReboot"
            $channel = Get-ConfigValue -section "Office" -key "Channel"
            $officeClientEdition = Get-ConfigValue -section "Office" -key "OfficeClientEdition"

            $odtUrl = "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_16731-20398.exe"
            $odtPath = $env:TEMP
            $odtFile = "$odtPath/ODTSetup.exe"
            $configurationXMLFile = "$odtPath\configuration.xml"

            Write-Log "Downloading Office Deployment Tool..."
            Write-SystemMessage -msg1 "Downloading Office Deployment Tool..."
            Invoke-WebRequest -Uri $odtUrl -OutFile $odtFile

            Write-Log "Creating configuration XML file..."
            Write-SystemMessage -msg1 "Creating configuration XML file..."
            @"
<Configuration>
  <Add OfficeClientEdition="$officeClientEdition" Channel="$channel">
    <Product ID="$productID">
      <Language ID="$languageID" />
    </Product>
  </Add>
  <Updates Enabled="$updatesEnabled" />
  <Display Level="$displayLevel" AcceptEULA="TRUE" />
  <Property Name="AUTOACTIVATE" Value="1" />
  <Property Name="PIDKEY" Value="$licenseKey" />
  <Setting Id="SETUP_REBOOT" Value="$setupReboot" />
</Configuration>
"@ | Out-File $configurationXMLFile

            Write-Log "Running the Office Deployment Tool..."
            Write-SystemMessage -msg1 "Running the Office Deployment Tool..."
            Start-Process $odtFile -ArgumentList "/quiet /extract:$odtPath" -Wait

            Write-Log "Downloading and installing Microsoft Office..."
            Write-SystemMessage -msg1 "Downloading and installing Microsoft Office..."
            $installProcess = Start-Process "$odtPath\Setup.exe" -ArgumentList "/configure `"$configurationXMLFile`"" -Wait -PassThru -WindowStyle Minimized

            if ($installProcess.ExitCode -eq 0) {
                Write-Log "Microsoft Office installation completed successfully."
                Write-SuccessMessage -msg "Microsoft Office installation completed successfully."
            } else {
                Write-Log "Failed to install Microsoft Office. Exit code: $($installProcess.ExitCode)"
                Write-ErrorMessage -msg "Failed to install Microsoft Office. Exit code: $($installProcess.ExitCode)"
            }

            # Clean up the extracted files and the zip file
            Remove-Item $odtFile
            Remove-Item $configurationXMLFile
        } else {
            Write-Log "Office configuration not found in configuration file. Skipping Office installation."
        }
    } catch {
        Write-Log "Error installing Microsoft Office: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error installing Microsoft Office: $($_.Exception.Message)"
        Return
    }
}

# Function to configure Taskbar Features
function Set-TaskbarFeatures {

    # Guard clause to check if the "Taskbar" section exists
    if (-not $config.ContainsKey("Taskbar")) {
        Write-Log "Taskbar section not found in the config. Skipping Taskbar settings configuration."
        return
    }
    
    Write-SystemMessage -title "Applying Taskbar Features"

    # Disable 'Meet Now' icon on Taskbar
    $disableMeetNow = Get-ConfigValue -section "Taskbar" -key "DisableMeetNow"
    if ($disableMeetNow -eq "TRUE") {
        Write-Log "Disabling 'Meet Now' icon on Taskbar."
        Write-SystemMessage -msg1 "- Disabling 'Meet Now' icon."
        try {
            # Use RegistryTouch to disable 'Meet Now'
            RegistryTouch -action add -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name "HideSCAMeetNow" -type "DWord" -value 1
            Write-SuccessMessage -msg "'Meet Now' icon disabled."
        } catch {
            Write-Log "Error disabling 'Meet Now' icon: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to disable 'Meet Now' icon."
        }
    } else {
        Write-Log "'Meet Now' icon not disabled. Skipping."
    }

    # Disable Taskbar Widgets (Weather, News, etc.)
    $disableWidgets = Get-ConfigValue -section "Taskbar" -key "DisableWidgets"
    if ($disableWidgets -eq "TRUE") {
        Write-Log "Disabling Taskbar Widgets (Weather, News, etc.)."
        Write-SystemMessage -msg1 "- Disabling Taskbar Widgets."
        try {
            # Use RegistryTouch to disable Widgets
            RegistryTouch -action add -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "TaskbarDa" -type "DWord" -value 0
            Write-SuccessMessage -msg "Taskbar Widgets disabled."
        } catch {
            Write-Log "Error disabling Taskbar Widgets: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to disable Taskbar Widgets."
        }
    } else {
        Write-Log "Taskbar Widgets not disabled. Skipping."
    }

    # Disable Task View button on Taskbar
    $disableTaskView = Get-ConfigValue -section "Taskbar" -key "DisableTaskView"
    if ($disableTaskView -eq "TRUE") {
        Write-Log "Disabling Task View button on Taskbar."
        Write-SystemMessage -msg1 "- Disabling Task View button."
        try {
            # Use RegistryTouch to disable Task View button
            RegistryTouch -action add -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "ShowTaskViewButton" -type "DWord" -value 0
            Write-SuccessMessage -msg "Task View button disabled."
        } catch {
            Write-Log "Error disabling Task View button: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to disable Task View button."
        }
    } else {
        Write-Log "Task View button not disabled. Skipping."
    }

    # Set Taskbar Alignment (Left or Center)
    $taskbarAlignment = Get-ConfigValue -section "Taskbar" -key "TaskbarAlignment"
    if ($taskbarAlignment) {
        Write-Log "Setting Taskbar Alignment to: $taskbarAlignment"
        Write-SystemMessage -msg1 "- Setting Taskbar Alignment to: " -msg2 $taskbarAlignment
        try {
            switch ($taskbarAlignment) {
                "Left" {
                    # Use RegistryTouch to set alignment to Left
                    RegistryTouch -action add -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "TaskbarAl" -type "DWord" -value 0
                }
                "Center" {
                    # Use RegistryTouch to set alignment to Center
                    RegistryTouch -action add -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "TaskbarAl" -type "DWord" -value 1
                }
                default {
                    Write-Log "Invalid Taskbar Alignment: $taskbarAlignment. Skipping."
                    return
                }
            }
            Write-Log "Taskbar Alignment set to $taskbarAlignment."
            # Restart explorer to apply the changes
            Stop-Process -Name explorer -Force
            Start-Process explorer
        } catch {
            Write-Log "Error setting Taskbar Alignment: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to set Taskbar Alignment."
        }
    } else {
        Write-Log "Taskbar Alignment not set. Missing configuration."
    }

    # Disable Search in Taskbar (online search)
    $disableSearch = Get-ConfigValue -section "Taskbar" -key "DisableSearch"
    if ($disableSearch -eq "TRUE") {
        Write-Log "Disabling online Search in Taskbar."
        Write-SystemMessage -msg1 "- Disabling online Search in Taskbar."
        try {
            # Use RegistryTouch to disable Bing Search and Cortana
            RegistryTouch -action add -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -name "BingSearchEnabled" -type "DWord" -value 0
            RegistryTouch -action add -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -name "CortanaConsent" -type "DWord" -value 0
            Write-SuccessMessage -msg "Online Search disabled in Taskbar."
        } catch {
            Write-Log "Error disabling online Search in Taskbar: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to disable online Search in Taskbar."
        }
    } else {
        Write-Log "Online Search not disabled in Taskbar. Skipping."
    }

    Write-Log "Taskbar features configuration completed."
    Write-SuccessMessage -msg "Taskbar features applied successfully."
}


# Function to configure the Theme Settings
function Set-ThemeSettings {

    # Guard clause to check if the "Theme" section exists
    if (-not $config.ContainsKey("Theme")) {
        Write-Log "Theme section not found in the config. Skipping Theme settings configuration."
        return
    }

    Write-SystemMessage -title "Applying Theme Settings"

    # Enable Dark Mode (TRUE or FALSE)
    $darkMode = Get-ConfigValue -section "Theme" -key "DarkMode"
    if ($darkMode) {
        $modeValue = if ($darkMode -eq "TRUE") { 0 } else { 1 }
        Write-Log "Setting Dark Mode to: $darkMode"
        Write-SystemMessage -msg1 "- Setting Dark Mode to: " -msg2 $darkMode
        try {
            # Use RegistryTouch to set the registry value
            RegistryTouch -action add -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -name "AppsUseLightTheme" -type "DWord" -value $modeValue
        } catch {
            Write-Log "Error setting Dark Mode: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to set Dark Mode."
        }
    } else {
        Write-Log "Dark Mode setting not provided. Skipping."
    }

    # Set Transparency Effects
    $transparencyEffects = Get-ConfigValue -section "Theme" -key "TransparencyEffects"
    if ($transparencyEffects) {
        $transparencyValue = if ($transparencyEffects -eq "TRUE") { 1 } else { 0 }
        Write-Log "Setting Transparency Effects to: $transparencyEffects"
        Write-SystemMessage -msg1 "- Setting Transparency Effects to: " -msg2 $transparencyEffects
        try {
            # Use RegistryTouch to set the registry value
            RegistryTouch -action add -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -name "EnableTransparency" -type "DWord" -value $transparencyValue
        } catch {
            Write-Log "Error setting Transparency Effects: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to set Transparency Effects."
        }
    } else {
        Write-Log "Transparency Effects not set. Missing configuration."
    }

    # Set Desktop Icon Size
    $desktopIconSize = Get-ConfigValue -section "Theme" -key "DesktopIconSize"
    if ($desktopIconSize) {
        Write-Log "Setting Desktop Icon Size to: $desktopIconSize"
        Write-SystemMessage -msg1 "- Setting Desktop Icon Size to: " -msg2 $desktopIconSize
        
        switch ($desktopIconSize) {
            "Small" { $iconSizeValue = 32 }
            "Medium" { $iconSizeValue = 48 }
            "Large" { $iconSizeValue = 64 }
            default { 
                Write-Log "Invalid Desktop Icon Size specified: $desktopIconSize. Skipping."
                return
            }
        }
        
        try {
            # Use RegistryTouch to set the registry value
            RegistryTouch -action add -path "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" -name "IconSize" -type "DWord" -value $iconSizeValue
            Write-Log "Desktop Icon Size set to $desktopIconSize ($iconSizeValue)."
        } catch {
            Write-Log "Error setting Desktop Icon Size: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to set Desktop Icon Size."
        }
    } else {
        Write-Log "Desktop Icon Size not set. Missing configuration."
    }

    # Set Wallpaper
    $wallpaperPath = Get-ConfigValue -section "Theme" -key "WallpaperPath"
    if ($wallpaperPath) {
        Write-Log "Setting wallpaper to: $wallpaperPath"
        Write-SystemMessage -msg1 "- Setting wallpaper to: " -msg2 $wallpaperPath

        if ($wallpaperPath -match "^https?://") {
            $tempWallpaperPath = "$env:TEMP\wallpaper.jpg"
            Write-Log "Downloading wallpaper from: $wallpaperPath"
            Invoke-WebRequest -Uri $wallpaperPath -OutFile $tempWallpaperPath
            $wallpaperPath = $tempWallpaperPath
        }

        try {
            $setwallpapersrc = @"
using System.Runtime.InteropServices;

public class Wallpaper
{
public const int SetDesktopWallpaper = 20;
public const int UpdateIniFile = 0x01;
public const int SendWinIniChange = 0x02;
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
private static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
public static void SetWallpaper(string path)
{
SystemParametersInfo(SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange);
}
}
"@
            Add-Type -TypeDefinition $setwallpapersrc

            [Wallpaper]::SetWallpaper($wallpaperPath)
            Write-Log "Wallpaper set successfully."
        }
        catch {
            Write-Log "Error setting wallpaper: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to set wallpaper."
        }
    } else {
        Write-Log "Wallpaper not set. Missing configuration."
    }

    # Set Lock Screen Image
    $lockScreenPath = Get-ConfigValue -section "Theme" -key "LockScreenPath"
    if ($lockScreenPath) {
        Write-Log "Setting lock screen image to: $lockScreenPath"
        Write-SystemMessage -msg1 "- Setting lock screen image to: " -msg2 $lockScreenPath

        if ($lockScreenPath -match "^https?://") {
            $tempLockScreenPath = "$env:TEMP\lockscreen.jpg"
            Write-Log "Downloading lock screen image from: $lockScreenPath"
            Invoke-WebRequest -Uri $lockScreenPath -OutFile $tempLockScreenPath
            $lockScreenPath = $tempLockScreenPath
        }

        try {
            $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
            # Use RegistryTouch to set the registry values
            RegistryTouch -action add -path $registryPath -name "LockScreenImagePath" -type "String" -value $lockScreenPath
            RegistryTouch -action add -path $registryPath -name "LockScreenImageUrl" -type "String" -value $lockScreenPath
            RegistryTouch -action add -path $registryPath -name "LockScreenImageStatus" -type "DWord" -value 1
            Write-Log "Lock screen image set successfully."
        } catch {
            Write-Log "Error setting lock screen image: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to set lock screen image."
        }
    } else {
        Write-Log "Lock screen image not set. Missing configuration."
    }

    # Restart Explorer for settings to take effect
    Stop-Process -Name explorer -Force
    Start-Sleep -Seconds 5
    if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) { Start-Process explorer }

    Write-Log "Theme Settings configuration completed."
    Write-SuccessMessage -msg "Theme Settings applied successfully."
}

# Function to configure System Tweaks
function Set-Tweaks {

    # Guard clause to check if the "Tweaks" section exists
    if (-not $config.ContainsKey("Tweaks")) {
        Write-Log "Tweaks section not found in the config. Skipping Tweaks settings configuration."
        return
    }

    Write-SystemMessage -title "Applying Tweaks"

    # Enable Classic Right-Click Menu (Windows 10 Style)
    $classicRightClickMenu = Get-ConfigValue -section "Tweaks" -key "ClassicRightClickMenu"
    if ($classicRightClickMenu -eq "TRUE") {
        Write-Log "Restoring Windows 10-style right-click menu."
        Write-SystemMessage -msg1 "- Enabling Windows 10-style right-click menu."
        try {
            # Use RegistryTouch to create the keys and set default values
            RegistryTouch -action add -path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -name "(Default)" -type "String" -value ""
            RegistryTouch -action add -path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -name "(Default)" -type "String" -value ""

            # Restart explorer to apply changes
            Stop-Process -Name explorer -Force
            Start-Process explorer
            Write-SuccessMessage -msg "Classic right-click menu enabled."
        } catch {
            Write-Log "Error restoring classic right-click menu: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to restore classic right-click menu."
        }
    } else {
        Write-Log "Classic right-click menu not enabled. Skipping."
    }

    # Enable God Mode on the Desktop
    $enableGodMode = Get-ConfigValue -section "Tweaks" -key "EnableGodMode"
    if ($enableGodMode -eq "TRUE") {
        Write-Log "Enabling God Mode on the desktop."
        Write-SystemMessage -msg1 "- Enabling God Mode on the desktop."
        try {
            $godModePath = Join-Path -Path ([System.Environment]::GetFolderPath('Desktop')) -ChildPath "GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
            
            # Create the GodMode folder with the correct name
            New-Item -ItemType Directory -Path $godModePath -Force | Out-Null
            Write-SuccessMessage -msg "God Mode enabled on the desktop."

        } catch {
            Write-Log "Error enabling God Mode: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to enable God Mode."
        }
    } else {
        Write-Log "God Mode not enabled. Skipping."
    }

    Write-Log "Tweaks configuration completed."
}


# Function to configure Privacy settings
function Set-PrivacySettings {

    # Guard clause to check if the "Privacy" section exists
    if (-not $config.ContainsKey("Privacy")) {
        Write-Log "Privacy section not found in the config. Skipping Privacy settings configuration."
        return
    }

    Write-SystemMessage -title "Configuring Privacy Settings"
    Write-Log "Configuring Privacy Settings"

    # Disable Personalized Advertising
    try {
        $disableAdvertising = Get-ConfigValue -section "Privacy" -key "DisablePersonalisedAdvertising"
        if ($disableAdvertising -eq "TRUE") {
            Write-Log "Disabling Personalized Advertising."
            Write-SystemMessage -msg1 "- Disabling Personalized Advertising."
            RegistryTouch -action "add" -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -name "Enabled" -type "DWord" -value 0 | Out-Null
            Write-SuccessMessage -msg "Personalized Advertising disabled."
        } else {
            Write-Log "Personalized Advertising not disabled. Skipping."
        }
    } catch {
        Write-Log "Error disabling Personalized Advertising: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to disable Personalized Advertising."
    }

    # Disable Start Menu Tracking and Telemetry
    try {
        $disableStartMenuTracking = Get-ConfigValue -section "Privacy" -key "DisableStartMenuTracking"
        if ($disableStartMenuTracking -eq "TRUE") {
            Write-Log "Disabling Start Menu Tracking and Telemetry."
            Write-SystemMessage -msg1 "- Disabling Start Menu Tracking and Telemetry."
            RegistryTouch -action "add" -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "Start_TrackProgs" -type "DWord" -value 0 | Out-Null
            Write-SuccessMessage -msg "Start Menu Tracking and Telemetry disabled."
        } else {
            Write-Log "Start Menu Tracking and Telemetry not disabled. Skipping."
        }
    } catch {
        Write-Log "Error disabling Start Menu Tracking: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to disable Start Menu Tracking and Telemetry."
    }

    # Disable Activity History
    try {
        $disableActivityHistory = Get-ConfigValue -section "Privacy" -key "DisableActivityHistory"
        if ($disableActivityHistory -eq "TRUE") {
            Write-Log "Disabling Activity History."
            Write-SystemMessage -msg1 "- Disabling Activity History."
            RegistryTouch -action "add" -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -name "ActivityHistoryEnabled" -type "DWord" -value 0 | Out-Null
            Write-SuccessMessage -msg "Activity History disabled."
        } else {
            Write-Log "Activity History not disabled. Skipping."
        }
    } catch {
        Write-Log "Error disabling Activity History: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to disable Activity History."
    }

    # Disable Clipboard Data Collection
    try {
        $disableClipboardHistory = Get-ConfigValue -section "Privacy" -key "DisableClipboardDataCollection"
        if ($disableClipboardHistory -eq "TRUE") {
            Write-Log "Disabling Clipboard Data Collection."
            Write-SystemMessage -msg1 "- Disabling Clipboard Data Collection."
            RegistryTouch -action "add" -path "HKCU:\Software\Microsoft\Clipboard" -name "EnableClipboardHistory" -type "DWord" -value 0 | Out-Null
            Write-SuccessMessage -msg "Clipboard Data Collection disabled."
        } else {
            Write-Log "Clipboard Data Collection not disabled. Skipping."
        }
    } catch {
        Write-Log "Error disabling Clipboard Data Collection: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to disable Clipboard Data Collection."
    }

    # Disable Start Menu Suggestions and Windows Advertising
    try {
        $disableStartMenuSuggestions = Get-ConfigValue -section "Privacy" -key "DisableStartMenuSuggestions"
        if ($disableStartMenuSuggestions -eq "TRUE") {
            Write-Log "Disabling Start Menu Suggestions and Windows Advertising."
            Write-SystemMessage -msg1 "- Disabling Start Menu Suggestions and Windows Advertising."
            RegistryTouch -action "add" -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -name "SubscribedContent-338389Enabled" -type "DWord" -value 0 | Out-Null
            Write-SuccessMessage -msg "Start Menu Suggestions and Windows Advertising disabled."
        } else {
            Write-Log "Start Menu Suggestions and Windows Advertising not disabled. Skipping."
        }
    } catch {
        Write-Log "Error disabling Start Menu Suggestions: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to disable Start Menu Suggestions and Windows Advertising."
    }

    Write-SuccessMessage -msg "Privacy settings configured successfully."
}

# Function to add registry entries
function Add-RegistryEntries {
    
    if ($config.ContainsKey("RegistryAdd")) {
        Write-SystemMessage -title "Adding Registry Entries"
        $registryEntries = $config["RegistryAdd"]
        try {
            # Check if the RegistryAdd section exists in the config
            # Loop through each entry in the RegistryAdd section
            foreach ($entry in $registryEntries.GetEnumerator()) {
                # Extract key parts from $entryString
                $path = if ($entry.Key -match 'Path="([^"]+)"') { $matches[1] } else { $null }
                $name = if ($entry.Key -match 'Name="([^"]+)"') { $matches[1] } else { $null }
                $type = if ($entry.Key -match 'Type="([^"]+)"') { $matches[1] } else { $null }
                $value = $entry.Value

                # Expand environment variables in the value
                $expandedValue = $ExecutionContext.InvokeCommand.ExpandString($value)

                # Check for null or empty values and log error, but continue loop
                if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($type) -or [string]::IsNullOrWhiteSpace($expandedValue)) {
                    $errorMessage = "One or more registry entry components are missing or improperly formatted. Please correct your configuration file. Path=$path, Name=$name, Type=$type, Value=$expandedValue"
                    Write-Log $errorMessage
                    Write-ErrorMessage -msg $errorMessage
                    continue  # Skip this entry and continue with the next one
                }

                # Log and apply the registry entry
                Write-SystemMessage -msg1 "- Adding registry entry: " -msg2 "Path=$path, Name=$name, Type=$type, Value=$expandedValue"
                Write-Log "Adding registry entry: Path=$path, Name=$name, Type=$type, Value=$expandedValue"

                # Use RegistryTouch function to add the registry entry and check for success
                try {
                    RegistryTouch -action "add" -path $path -name $name -type $type -value $expandedValue | Out-Null
                }
                catch {
                    Write-ErrorMessage -msg "Failed to add registry entry: Path=$path, Name=$name, Type=$type, Value=$expandedValue. Error: $($_.Exception.Message)"
                    Write-Log "Failed to add registry entry: Path=$path, Name=$name, Type=$type, Value=$expandedValue. Error: $($_.Exception.Message)"
                    continue
                }
            }
        }
        catch {
            Write-ErrorMessage -msg "Error adding registry entries: $($_.Exception.Message)"
            Write-Log "Error adding registry entries: $($_.Exception.Message)"
            Return
        }

        Write-Log "Add Registry entries complete."
    }
    else {
        Write-Log "No registry entries to add. Missing configuration."
    }

}

# Function to remove registry entries
function Remove-RegistryEntries {
    try {
        # Check if the RegistryRemove section exists in the config
        if ($config.ContainsKey("RegistryRemove")) {
            Write-SystemMessage -title "Removing Registry Entries"
            $registryEntries = $config["RegistryRemove"]

            # Loop through each entry in the RegistryRemove section
            foreach ($entry in $registryEntries.GetEnumerator()) {
                # Extract key parts from $entryString
                $path = if ($entry.Key -match 'Path="([^"]+)"') { $matches[1] } else { $null }
                $name = if ($entry.Key -match 'Name="([^"]+)"') { $matches[1] } else { $null }
                $type = if ($entry.Key -match 'Type="([^"]+)"') { $matches[1] } else { $null }
                $value = $entry.Value

                # Check for null or empty values and log error, but continue loop
                if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($type) -or [string]::IsNullOrWhiteSpace($value)) {
                    $errorMessage = "One or more registry entry components are missing or improperly formatted. Please correct your configuration file. Path=$path, Name=$name, Type=$type, Value=$value"
                    Write-Log $errorMessage
                    Write-ErrorMessage -msg $errorMessage
                    continue  # Skip this entry and continue with the next one
                }

                # Log and attempt to remove the registry entry
                Write-SystemMessage -msg1 "- Removing registry entry: " -msg2 "Path=$path, Name=$name"
                Write-Log "Removing registry entry: Path=$path, Name=$name, Type=$type, Value=$value"

                # Use RegistryTouch function to remove the registry entry and check for success
                try {
                    RegistryTouch -action "remove" -path $path -name $name | Out-Null
                } catch {
                    Write-ErrorMessage -msg "Failed to remove registry entry: Path=$path, Name=$name, Type=$type, Value=$value. Error: $($_.Exception.Message)"
                    Write-Log "Failed to remove registry entry: Path=$path, Name=$name, Type=$type, Value=$value. Error: $($_.Exception.Message)"
                    continue
                }
            }

                Write-Log "Remove Registry entries complete."
        } else {
            Write-Log "No registry entries to remove. Missing configuration."
        }
    } catch {
        Write-ErrorMessage -msg "Error removing registry entries: $($_.Exception.Message)"
        Write-Log "Error removing registry entries: $($_.Exception.Message)"
        Return
    }
}

# Function to configure power settings
function Set-PowerSettings {
    
    # Guard clause to check if the "PowerSettings" section exists
    if (-not $config.ContainsKey("PowerSettings")) {
        Write-Log "PowerSettings section not found in the config. Skipping PowerSettings settings configuration."
        return
    }

    Write-SystemMessage -title "Configuring Power Settings"

    # Set Power Plan
    $powerPlan = Get-ConfigValue -section "PowerSettings" -key "PowerPlan"
    if ($powerPlan) {
        Write-Log "Setting Power Plan to: $powerPlan"
        Write-SystemMessage -msg1 "- Setting Power Plan to: " -msg2 $powerPlan

        try {
            # Map the power plan name to the system power plan using WMI
            $changePowerPlan = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerPlan -Filter "ElementName = '$powerPlan'"
            if ($changePowerPlan) {
                $changePowerPlan.Activate()
                Write-Log "Power Plan set to: $powerPlan"
                Write-SuccessMessage -msg "Power Plan set to: $powerPlan"
            } else {
                Write-Log "Error: Power plan $powerPlan not found."
                Write-ErrorMessage -msg "Power Plan not found: $powerPlan"
            }
        } catch {
            Write-Log "Error setting Power Plan: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to set Power Plan."
        }
    } else {
        Write-Log "Power Plan not set. Missing configuration."
    }

    # Set Sleep Timeout
    $sleepTimeout = Get-ConfigValue -section "PowerSettings" -key "SleepTimeout"
    if ($sleepTimeout) {
        Write-Log "Setting Sleep Timeout to: $sleepTimeout minutes"
        Write-SystemMessage -msg1 "- Setting Sleep Timeout to: " -msg2 "$sleepTimeout minutes"
        try {
            powercfg -change -monitor-timeout-ac $sleepTimeout
            Write-Log "Sleep Timeout set to: $sleepTimeout minutes"
            Write-SuccessMessage -msg "Sleep Timeout set to: $sleepTimeout minutes"
        } catch {
            Write-Log "Error setting Sleep Timeout: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to set Sleep Timeout."
        }
    } else {
        Write-Log "Sleep Timeout not set. Missing configuration."
    }

    # Set Hibernate Timeout
    $hibernateTimeout = Get-ConfigValue -section "PowerSettings" -key "HibernateTimeout"
    if ($hibernateTimeout) {
        Write-Log "Setting Hibernate Timeout to: $hibernateTimeout minutes"
        Write-SystemMessage -msg1 "- Setting Hibernate Timeout to: " -msg2 "$hibernateTimeout minutes"
        try {
            powercfg -change -standby-timeout-ac $hibernateTimeout
            Write-Log "Hibernate Timeout set to: $hibernateTimeout minutes"
            Write-SuccessMessage -msg "Hibernate Timeout set to: $hibernateTimeout minutes"
        } catch {
            Write-Log "Error setting Hibernate Timeout: $($_.Exception.Message)"
            Write-ErrorMessage -msg "Failed to set Hibernate Timeout."
        }
    } else {
        Write-Log "Hibernate Timeout not set. Missing configuration."
    }

    Write-Log "Power settings configuration completed."
}

# Function to configure Windows updates
function Set-WindowsUpdates {

    # Guard clause to check if the "WindowsUpdate" section exists
    if (-not $config.ContainsKey("WindowsUpdate")) {
        Write-Log "WindowsUpdate section not found in the config. Skipping WindowsUpdate settings configuration."
        return
    }


    try {
        $noAutoUpdate = Get-ConfigValue -section "WindowsUpdate" -key "NoAutoUpdate"
        $auOptions = Get-ConfigValue -section "WindowsUpdate" -key "AUOptions"
        $autoInstallMinorUpdates = Get-ConfigValue -section "WindowsUpdate" -key "AutoInstallMinorUpdates"
        $scheduledInstallDay = Get-ConfigValue -section "WindowsUpdate" -key "ScheduledInstallDay"
        $scheduledInstallTime = Get-ConfigValue -section "WindowsUpdate" -key "ScheduledInstallTime"

        Write-SystemMessage -title "Configuring Windows Updates"

        Write-Log "NoAutoUpdate: $noAutoUpdate"
        Write-Log "AUOptions: $auOptions"
        Write-Log "ScheduledInstallDay: $scheduledInstallDay"
        Write-Log "ScheduledInstallTime: $scheduledInstallTime"

        if ($noAutoUpdate -eq "TRUE") {
            Write-Log "Disabling automatic windows updates..."
            Write-SystemMessage -msg1 "- Disabling all automatic updates."
            RegistryTouch -action "add" -path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -name "NoAutoUpdate" -type "DWord" -value 1 | Out-Null
            Write-Log "Automatic updates disabled."
            Write-SystemMessage -msg1 "- Automatic updates disabled." -msg1Color "Green"
        } elseif ($noAutoUpdate -eq "FALSE") {
            Write-Log "Enabling automatic windows updates..."
            Write-SystemMessage -msg1 "- Enabling automatic updates."
            RegistryTouch -action "add" -path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -name "NoAutoUpdate" -type "DWord" -value 0 | Out-Null

            if ($auOptions -and $scheduledInstallDay -and $scheduledInstallTime) {
                Write-Log "Setting AUOptions to: $auOptions"
                Write-SystemMessage -msg1 "- Setting AUOptions to: " -msg2 $auOptions
                RegistryTouch -action "add" -path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -name "AUOptions" -type "DWord" -value $auOptions | Out-Null

                Write-Log "Setting ScheduledInstallDay to: $scheduledInstallDay"
                Write-SystemMessage -msg1 "- Setting ScheduledInstallDay to: " -msg2 $scheduledInstallDay
                RegistryTouch -action "add" -path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -name "ScheduledInstallDay" -type "DWord" -value $scheduledInstallDay | Out-Null

                Write-Log "Setting ScheduledInstallTime to: $scheduledInstallTime"
                Write-SystemMessage -msg1 "- Setting ScheduledInstallTime to: " -msg2 $scheduledInstallTime
                RegistryTouch -action "add" -path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -name "ScheduledInstallTime" -type "DWord" -value $scheduledInstallTime | Out-Null
            } else {
                Write-Log "Missing AUOptions, ScheduledInstallDay, or ScheduledInstallTime configuration. Skipping scheduled updates settings."
                Write-SystemMessage -msg1 "Missing AUOptions, ScheduledInstallDay, or ScheduledInstallTime configuration. Skipping scheduled updates settings." -msg1Color "Yellow"
            }

            if ($autoInstallMinorUpdates -eq "TRUE") {
                Write-Log "Enabling AutoInstallMinorUpdates"
                Write-SystemMessage -msg1 "- Enabling AutoInstallMinorUpdates."
                RegistryTouch -action "add" -path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -name "AutoInstallMinorUpdates" -type "DWord" -value 1 | Out-Null
            } elseif ($autoInstallMinorUpdates -eq "FALSE") {
                Write-Log "Disabling AutoInstallMinorUpdates"
                Write-SystemMessage -msg1 "- Disabling AutoInstallMinorUpdates."
                RegistryTouch -action "add" -path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -name "AutoInstallMinorUpdates" -type "DWord" -value 0 | Out-Null
            } else {
                Write-Log "No valid AutoInstallMinorUpdates setting provided."
                Write-SystemMessage -msg1 "No valid AutoInstallMinorUpdates setting provided." -msg1Color "Yellow"
            }

            Write-Log "Windows updates configured successfully."
            Write-SystemMessage -msg1 "- Windows updates configured successfully." -msg1Color "Green"
        } else {
            Write-Log "No valid NoAutoUpdate setting provided."
        }
    } catch {
        Write-Log "Error configuring Windows updates: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error configuring Windows updates: $($_.Exception.Message)"
        Return
    }
}

# Function to set optional windows features and services
function Set-Services {
    
    try {
        $services = $config["Services"]
        if ($services) {
            Write-SystemMessage -title "Configuring Services"
            foreach ($service in $services.GetEnumerator()) {
                $serviceName = $service.Key
                $serviceAction = $service.Value.ToLower()
                try {
                    # Check if the feature is installed or not
                    $featureStatus = Get-WindowsOptionalFeature -Online -FeatureName $serviceName

                    if ($serviceAction -eq "enabled") {
                        if ($featureStatus.State -eq "Disabled") {
                            Write-SystemMessage -msg1 "- Enabling: " -msg2 $serviceName
                            Write-Log "Enabling service: $serviceName"
                            Enable-WindowsOptionalFeature -FeatureName $serviceName -Online -NoRestart -LogLevel 1 | Out-Null
                            Write-SystemMessage -msg1 "- $serviceName enabled successfully." -msg1Color "Green"
                        } else {
                            Write-Log "$serviceName is already enabled. Skipping."
                            Write-SystemMessage -msg1 "$serviceName is already enabled. Skipping." -msg1Color "Cyan"
                        }
                    } elseif ($serviceAction -eq "disabled") {
                        if ($featureStatus.State -eq "Enabled") {
                            Write-SystemMessage -msg1 "- Disabling: " -msg2 $serviceName
                            Write-Log "Disabling service: $serviceName"
                            Disable-WindowsOptionalFeature -FeatureName $serviceName -Online -NoRestart -LogLevel 1 | Out-Null
                            Write-SystemMessage -msg1 "- $serviceName disabled successfully." -msg1Color "Green"
                        } else {
                            Write-Log "$serviceName is already disabled. Skipping."
                            Write-SystemMessage -msg1 "$serviceName is already disabled. Skipping." -msg1Color "Cyan"
                        }
                    } else {
                        Write-SystemMessage -msg1 "- Invalid service action for: " -msg2 $serviceName -msg1Color "Red"
                        Write-Log "Invalid service action for ${serviceName}: $serviceAction"
                    }
                } catch {
                    Write-ErrorMessage -msg "$serviceName was not found as an optional service, check spelling and fix the configuration file."
                    Write-Log "Error configuring service ${serviceName}: $($_.Exception.Message)"
                }
            }
            Write-Log "Service configurations applied successfully."
            Write-SuccessMessage
        } else {
            Write-Log -msg1 "No services to configure. Missing configuration."
        }
    } catch {
        Write-Log "Error configuring services: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error configuring services: $($_.Exception.Message)"
        Return
    }
}

# Function to configure security settings
function Set-SecuritySettings {

    # Guard clause to check if "Security" section exists in the config file
    if (-not $config.ContainsKey("Security")) {
        Write-Log "Security section not found in the config. Skipping Security settings configuration."
        return
    }

    Write-SystemMessage -title "Configuring Security Settings"
    Write-Log "Configuring Security Settings"

    # Set UAC level
    try {
        $uacLevel = Get-ConfigValue -section "Security" -key "UACLevel"
        if ($uacLevel) {
            Write-Log "Setting UAC level to: $uacLevel"
            Write-SystemMessage -msg1 "- Setting UAC level to: " -msg2 $uacLevel
            RegistryTouch -action "add" -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -name "ConsentPromptBehaviorAdmin" -type "DWord" -value $uacLevel | Out-Null
            Write-SuccessMessage -msg "UAC level set to $uacLevel."
        } else {
            Write-Log "UAC level not set. Skipping."
        }
    } catch {
        Write-Log "Error setting UAC level: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to set UAC level."
    }

    # Disable/Enable Telemetry
    try {
        $disableTelemetry = Get-ConfigValue -section "Security" -key "DisableTelemetry"
        if ($disableTelemetry) {
            $telemetryValue = if ($disableTelemetry -eq "TRUE") { 0 } else { 1 }
            Write-Log "Setting telemetry to: $disableTelemetry"
            Write-SystemMessage -msg1 "- Configuring telemetry settings."
            
            $telemetryKeys = @(
                @{path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; name="AllowTelemetry"; value=$telemetryValue; type="DWord"},
                @{path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; name="AllowTelemetry"; value=$telemetryValue; type="DWord"},
                @{path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; name="MaxTelemetryAllowed"; value=$telemetryValue; type="DWord"}
            )
            foreach ($key in $telemetryKeys) {
                RegistryTouch -action "add" -path $key.path -name $key.name -type $key.type -value $key.value | Out-Null
            }
            Write-SuccessMessage -msg "Telemetry settings applied."
        } else {
            Write-Log "Telemetry not configured. Skipping."
        }
    } catch {
        Write-Log "Error configuring telemetry: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to configure telemetry."
    }

    # Show/Hide file extensions
    try {
        $showFileExtensions = Get-ConfigValue -section "Security" -key "ShowFileExtensions"
        if ($showFileExtensions) {
            $fileExtValue = if ($showFileExtensions -eq "TRUE") { 0 } else { 1 }
            Write-Log "Configuring file extensions visibility to: $showFileExtensions"
            Write-SystemMessage -msg1 "- Configuring file extensions visibility."
            RegistryTouch -action "add" -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "HideFileExt" -type "DWord" -value $fileExtValue | Out-Null
            Write-SuccessMessage -msg "File extensions visibility configured."
        } else {
            Write-Log "File extensions visibility not set. Skipping."
        }
    } catch {
        Write-Log "Error configuring file extensions: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to configure file extensions."
    }

    # Disable AutoPlay and AutoRun
    try {
        $disableAutoPlay = Get-ConfigValue -section "Security" -key "DisableAutoPlay"
        if ($disableAutoPlay -eq "TRUE") {
            Write-Log "Disabling AutoPlay and AutoRun."
            Write-SystemMessage -msg1 "- Disabling AutoPlay and AutoRun."
            RegistryTouch -action "add" -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name "NoDriveTypeAutoRun" -type "DWord" -value 255 | Out-Null
            Write-SuccessMessage -msg "AutoPlay and AutoRun disabled."
        } else {
            Write-Log "AutoPlay and AutoRun not disabled. Skipping."
        }
    } catch {
        Write-Log "Error disabling AutoPlay and AutoRun: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to disable AutoPlay and AutoRun."
    }

    # Disable SMBv1
    try {
        $disableSMBv1 = Get-ConfigValue -section "Security" -key "DisableSMBv1"
        if ($disableSMBv1 -eq "TRUE") {
            Write-Log "Disabling SMBv1."
            Write-SystemMessage -msg1 "- Disabling SMBv1."
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
            Write-SuccessMessage -msg "SMBv1 disabled."
        } else {
            Write-Log "SMBv1 not disabled. Skipping."
        }
    } catch {
        Write-Log "Error disabling SMBv1: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to disable SMBv1."
    }

    # Disable Remote Desktop
    try {
        $disableRemoteDesktop = Get-ConfigValue -section "Security" -key "DisableRemoteDesktop"
        if ($disableRemoteDesktop -eq "TRUE") {
            Write-Log "Disabling Remote Desktop."
            Write-SystemMessage -msg1 "- Disabling Remote Desktop."
            RegistryTouch -action "add" -path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -name "fDenyTSConnections" -type "DWord" -value 1 | Out-Null
            Write-SuccessMessage -msg "Remote Desktop disabled."
        } else {
            Write-Log "Remote Desktop not disabled. Skipping."
        }
    } catch {
        Write-Log "Error disabling Remote Desktop: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Failed to disable Remote Desktop."
    }

    Write-SuccessMessage -msg "Security settings configured successfully."
}

# Function to manage BitLocker with a check for existing encryption
function Set-Bitlocker {

    $enableBitlocker = Get-ConfigValue -section "Security" -key "EnableBitlocker"
    $bitlockerTarget = Get-ConfigValue -section "Security" -key "BitlockerTarget"

    if (-not $enableBitlocker) {
        Write-ErrorMessage "EnableBitlocker is set to false. Skipping BitLocker configuration."
        Write-Log "EnableBitlocker is set to false. Skipping BitLocker configuration."
        return
    }

    if (-not $bitlockerTarget) {
        Write-ErrorMessage "BitlockerTarget not set in config file. Skipping BitLocker configuration."
        Write-Log "BitlockerTarget not set. Skipping BitLocker configuration."
        return
    }

    try {
        Write-SystemMessage -title "Configuring BitLocker"

        if ($enableBitlocker -eq "TRUE") {
            $bitlockerStatus = Get-BitLockerVolume -MountPoint $bitlockerTarget

            if ($bitlockerStatus.ProtectionStatus -eq 'On') {
                Write-Log "BitLocker is already enabled on $bitlockerTarget. Skipping."
                Write-SystemMessage -msg1 "- BitLocker already enabled on $bitlockerTarget. Skipping." -msg1Color "Green"
            } else {
                Write-Log "Enabling BitLocker on $bitlockerTarget"
                Enable-BitLocker -MountPoint $bitlockerTarget -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -SkipHardwareTest -ErrorAction Stop
                Write-SystemMessage -msg1 "- BitLocker enabled on $bitlockerTarget." -msg1Color "Green"
            }

        } elseif ($enableBitlocker -eq "FALSE") {
            $bitlockerStatus = Get-BitLockerVolume -MountPoint $bitlockerTarget
            if ($bitlockerStatus.ProtectionStatus -eq 'Off') {
                Write-Log "BitLocker is already disabled on $bitlockerTarget. Skipping."
                Write-SystemMessage -msg1 "- BitLocker already disabled on $bitlockerTarget. Skipping." -msg1Color "Green"
            } else {
                Write-Log "Disabling BitLocker on $bitlockerTarget"
                Disable-BitLocker -MountPoint $bitlockerTarget -ErrorAction Stop
                Write-SystemMessage -msg1 "- BitLocker disabled on $bitlockerTarget." -msg1Color "Green"
            }
        }

    } catch {
        Write-ErrorMessage -msg "Error configuring BitLocker: $($_.Exception.Message)"
        Write-Log "Error configuring BitLocker: $($_.Exception.Message)"
        return
    }
}


# Function to set environment variables
function Set-EnvironmentVariables {
    try {
        $environmentVariables = $config["EnvironmentVariables"]
        if ($environmentVariables) {
            Write-SystemMessage -title "Setting Environment Variables"
            foreach ($key in $environmentVariables.Keys) {
                $value = $environmentVariables[$key]
                Write-SystemMessage -msg1 "- Setting: " -msg2 "$key=$value"
                Write-Log "Setting environment variable: $key=$value"
                [System.Environment]::SetEnvironmentVariable($key, $value, "Machine")
                Write-SystemMessage -msg1 "- Environment variable $key set to $value." -msg1Color "Green"
            }
            Write-Log "Environment variables set successfully."
            Write-SuccessMessage -msg "Environment variables set successfully."
        } else {
            Write-Log "No environment variables set. Missing configuration."
        }
    } catch {
        Write-Log "Error setting environment variables: $($_.Exception.Message)"
        Write-ErrorMessage -msg "Error setting environment variables: $($_.Exception.Message)"
        Return
    }
}

# Function to install Chrome Enterprise
function Install-ChromeEnterprise {

    $InstallGoogleChrome = Get-ConfigValue -section "Google" -key "InstallGoogleChrome"

    if (!$InstallGoogleChrome) {
        Write-Log "Skipping Google Chrome Enterprise installation. Missing configuration."
        return
    }

    if ($InstallGoogleChrome -ne "TRUE") {
        return
    }

    $chromeFileName = if ([Environment]::Is64BitOperatingSystem) {
        'googlechromestandaloneenterprise64.msi'
    } else {
        'googlechromestandaloneenterprise.msi'
    }

    $chromeUrl = "https://dl.google.com/chrome/install/$chromeFileName"
    
    if (Test-ProgramInstalled 'Google Chrome') {
        Write-SystemMessage -msg1 "- Google Chrome Enterprise is already installed. Skipping installation." -msg1Color "Cyan"
        Write-Log "Google Chrome Enterprise already installed. Skipping..."
    } else {
        Write-SystemMessage -msg1 "- Downloading: " -msg2 "Google Chrome Enterprise"
        Write-Log "Downloading Chrome from $chromeUrl"
        Invoke-WebRequest -Uri $chromeUrl -OutFile "$env:TEMP\$chromeFileName" | Out-Null

        try {
            $arguments = "/i ""$env:TEMP\$chromeFileName"" /qn"
            $installProcess = Start-Process msiexec.exe -ArgumentList $arguments -PassThru -Wait

            if ($installProcess.ExitCode -eq 0) {
                Write-SystemMessage -msg1 "- Google Chrome Enterprise installed successfully." -msg1Color "Green"
                Write-Log "Chrome Enterprise installed."

                # Use RegistryTouch to make relevant registry changes if needed
                RegistryTouch -action add -path "HKLM:\Software\Policies\Google\Chrome" -name "EnterpriseInstall" -type "DWord" -value 1 | Out-Null
            } else {
                Write-ErrorMessage -msg "Failed to install Google Chrome Enterprise. Exit code: $($installProcess.ExitCode)"
                Write-Log "Failed to install Chrome Enterprise. Exit code: $($installProcess.ExitCode)"
            }
        } finally {
            Remove-Item -Path "$env:TEMP\$chromeFileName" -Force -ErrorAction SilentlyContinue
        }
    }
}


# Function to install GCPW
function Install-GCPW {
    $installGCPW = Get-ConfigValue -section "Google" -key "InstallGCPW"

    if ($installGCPW -eq "TRUE") {
        Write-SystemMessage -title "Installing Google Credential Provider for Windows (GCPW)"
        
        # Check for the EnrollmentToken, which is required
        if (-not (Get-ConfigValue -section "Google" -key "GCPW-EnrollmentToken")) {
            Write-SystemMessage -msg1 "Skipping GCPW installation due to missing EnrollmentToken." -msg1Color "Cyan"
            Write-Log "Skipping GCPW installation due to missing EnrollmentToken."
            return
        }

        $googleEnrollmentToken = Get-ConfigValue -section "Google" -key "GCPW-EnrollmentToken"
        $domainsAllowedToLogin = Get-ConfigValue -section "Google" -key "DomainsAllowedToLogin"  # Optional

        $gcpwFileName = if ([Environment]::Is64BitOperatingSystem) {
            'gcpwstandaloneenterprise64.msi'
        } else {
            'gcpwstandaloneenterprise.msi'
        }

        $gcpwUrl = "https://dl.google.com/credentialprovider/$gcpwFileName"
        if (Test-ProgramInstalled 'Credential Provider') {
            Write-SystemMessage -msg1 "- Google Credential Provider for Windows (GCPW) is already installed. Skipping installation." -msg1Color "Cyan"
            Write-Log "GCPW already installed. Skipping..."
        } else {
            Write-SystemMessage -msg1 "- Downloading: " -msg2 "Google Credential Provider for Windows (GCPW)"
            Write-Log "Downloading GCPW from $gcpwUrl"
            Invoke-WebRequest -Uri $gcpwUrl -OutFile "$env:TEMP\$gcpwFileName"

            try {
                $arguments = "/i ""$env:TEMP\$gcpwFileName"" /quiet"
                $installProcess = Start-Process msiexec.exe -ArgumentList $arguments -PassThru -Wait

                if ($installProcess.ExitCode -eq 0) {
                    Write-SystemMessage -msg1 "- Google Credential Provider for Windows (GCPW) installed successfully." -msg1Color "Green"
                    Write-Log "GCPW Installation completed successfully!"
                    
                    # Set the required EnrollmentToken
                    RegistryTouch -action add -path "HKLM:\SOFTWARE\Policies\Google\CloudManagement" -name "EnrollmentToken" -type "String" -value $googleEnrollmentToken | Out-Null
                    
                    # Only set domains_allowed_to_login if it was provided
                    if ($domainsAllowedToLogin) {
                        RegistryTouch -action add -path "HKLM:\Software\Google\GCPW" -name "domains_allowed_to_login" -type "String" -value $domainsAllowedToLogin | Out-Null
                        Write-SystemMessage -msg1 "- Domains allowed to login has been set successfully." -msg1Color "Green"
                        Write-Log 'Domains allowed to login has been set successfully'
                    } else {
                        Write-Log 'DomainsAllowedToLogin not provided. Skipping setting domains.'
                    }
                } else {
                    Write-ErrorMessage -msg "- Failed to install Google Credential Provider for Windows (GCPW). Exit code: $($installProcess.ExitCode)"
                    Write-Log "Failed to install GCPW. Exit code: $($installProcess.ExitCode)"
                }
            } finally {
                Remove-Item -Path "$env:TEMP\$gcpwFileName" -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        Write-SuccessMessage -msg "Google Credential Provider for Windows (GCPW) installation completed."
    } else {
        Write-Log "Skipping Google Credential Provider for Windows (GCPW) installation. Missing configuration."
    }
}



# Function to install Google Drive
function Install-GoogleDrive {

    $installGoogleDrive = Get-ConfigValue -section "Google" -key "InstallGoogleDrive"

    if (!$installGoogleDrive) {
        Write-Log "Skipping Google Drive installation. Missing configuration."
        return
    }

    if ($installGoogleDrive -ne "TRUE") {
        return
    }

    $driveFileName = 'GoogleDriveFSSetup.exe'
    $driveUrl = "https://dl.google.com/drive-file-stream/$driveFileName"

    if (Test-ProgramInstalled 'Google Drive') {
        Write-SystemMessage -msg1 "- Google Drive is already installed. Skipping installation." -msg1Color "Cyan"
        Write-Log 'Google Drive already installed. Skipping...'
    } else {
        Write-SystemMessage -msg1 "- Downloading: " -msg2 "Google Drive"
        Write-Log "Downloading Google Drive from $driveUrl"
        Invoke-WebRequest -Uri $driveUrl -OutFile "$env:TEMP\$driveFileName" | Out-Null

        try {
            Start-Process -FilePath "$env:TEMP\$driveFileName" -Verb runAs -ArgumentList '--silent' -Wait
            Write-SystemMessage -msg1 "- Google Drive installed successfully." -msg1Color "Green"
            Write-Log 'Google Drive Installation completed successfully!'
            
            # Use RegistryTouch to make any registry changes if necessary
            RegistryTouch -action add -path "HKLM:\Software\Google\Drive" -name "DriveInstallationStatus" -type "DWord" -value 1 | Out-Null
            
        } catch {
            Write-ErrorMessage -msg "Google Drive Installation failed!"
            Write-Log "Google Drive installation failed! Error: $($_.Exception.Message)"
        } finally {
            Remove-Item -Path "$env:TEMP\$driveFileName" -Force -ErrorAction SilentlyContinue
        }
    }
}


# Function to import tasks individually
function Import-Tasks {
    try {
        # Check if "Tasks" section is present in the configuration
        $tasksSection = $config["Tasks"]
        if (-not $tasksSection) {
            Write-Log "No individual tasks specified. Missing configuration."
            return
        }

        Write-SystemMessage -title "Importing Scheduled Tasks"

        foreach ($key in $tasksSection.Keys) {
            
            # Proceed only if the key is not "TaskRepository" as this is handled by the Import-TaskRepository function
            if ($key -eq "TaskRepository") {
                continue
            }

            else {
                $taskFile = $tasksSection[$key]

                # Extract the file name from the task file (works for URLs, local paths, or network shares)
                $fileName = Split-Path -Leaf $taskFile
                $tempTaskFile = Join-Path $env:TEMP $fileName

                try {
                    # Check if it's a remote URL or a local/network path
                    if ($taskFile -match "^https?://") {
                        # Handle remote URL
                        Write-Log "Downloading task file from remote URL: $taskFile"
                        Write-SystemMessage -msg1 "- Downloading task file from: " -msg2 $taskFile
                        
                        # Download the task file
                        Invoke-WebRequest -Uri $taskFile -OutFile $tempTaskFile
                    }
                    elseif (Test-Path $taskFile) {
                        # Handle local or network file
                        Write-Log "Copying task file from local/network path: $taskFile"
                        Write-SystemMessage -msg1 "- Copying task file from: " -msg2 $taskFile
                        
                        # Copy the task file to the temp directory
                        Copy-Item -Path $taskFile -Destination $tempTaskFile -Force
                    }
                    else {
                        throw "The task file does not exist or is inaccessible: $taskFile"
                    }

                    # Import the task using Register-ScheduledTask
                    Write-SystemMessage -msg1 "- Importing task: " -msg2 $fileName
                    Write-Log "Importing task: $fileName"

                    Register-ScheduledTask -TaskName $key -Xml (Get-Content $tempTaskFile | Out-String) -Force | Out-Null

                    Write-SystemMessage -msg1 "- Successfully imported task:" -msg2 "$fileName"
                    Write-Log "Successfully imported task: $fileName"
                }
                catch {
                    Write-ErrorMessage -msg "Failed to import task: $fileName - $($_.Exception.Message)"
                    Write-Log "Error: Failed to import task ${taskFile}: $($_.Exception.Message)"
                    return
                }
            }
        }
        Write-Log "Scheduled task(s) import complete."
        Write-SuccessMessage -msg "Scheduled task(s) import complete."
    }
    catch {
        Write-ErrorMessage -msg "Error importing task(s): $($_.Exception.Message)"
        Write-Log "Error importing tasks: $($_.Exception.Message)"
        return
    }
}

# Function to bulk import tasks repository from GitHub repository or ZIP file online
function Import-TaskRepository {
    try {
        # Check if "Tasks" section and "TaskRepository" key is present in the configuration
        $taskRepositoryUrl = Get-ConfigValue -section "Tasks" -key "TaskRepository"
        if (-not $taskRepositoryUrl) {
            Write-Log "No task repository specified. Missing configuration."
            return
        }

        Write-SystemMessage -title "Importing Task Repository"
        Write-Log "Starting task repository import from $taskRepositoryUrl"

        # Set up a temporary folder to store the task files
        $tempFolder = "$env:TEMP\TaskRepository"
        if (-not (Test-Path $tempFolder)) {
            New-Item -ItemType Directory -Path $tempFolder | Out-Null
        }

        # Check if the repository is hosted on GitHub
        if ($taskRepositoryUrl -match "github.com") {
            # Handle GitHub repositories
            Write-Log "Detected GitHub repository. Downloading task files from GitHub..."
            Write-SystemMessage -msg1 "- Downloading task files from GitHub repository."

            $taskFilesPage = Invoke-WebRequest -Uri $taskRepositoryUrl -UseBasicParsing

            # Fetch the XML task files from GitHub
            $taskFileLinks = $taskFilesPage.Links | Where-Object { $_.href -match "\.xml$" }

            foreach ($link in $taskFileLinks) {
                $fileUrl = "https://github.com" + $link.href.Replace("/blob/", "/raw/")
                $fileName = [System.IO.Path]::GetFileName($link.href)

                # Download each task XML file
                Write-Log "Downloading $fileName from: $fileUrl"
                Invoke-WebRequest -Uri $fileUrl -OutFile (Join-Path -Path $tempFolder -ChildPath $fileName)

                Write-Log "$fileName downloaded successfully."
            }
        } elseif ($taskRepositoryUrl -match "\.zip$") {
            # Handle ZIP files from other sources
            Write-Log "Detected ZIP file repository. Downloading and extracting..."
            Write-SystemMessage -msg1 "- Downloading and extracting ZIP repository."

            $zipFile = "$env:TEMP\taskrepository.zip"
            Invoke-WebRequest -Uri $taskRepositoryUrl -OutFile $zipFile
            Expand-Archive -Path $zipFile -DestinationPath $tempFolder -Force
            Remove-Item $zipFile

            Write-Log "ZIP file extracted to $tempFolder."
        } else {
            Write-Log "Unsupported repository format. Only GitHub or ZIP repositories are supported."
            Write-ErrorMessage -msg "Unsupported task repository format."
            return
        }

        # Import all the downloaded/extracted XML task files
        $xmlTaskFiles = Get-ChildItem -Path $tempFolder -Filter *.xml
        foreach ($taskFile in $xmlTaskFiles) {
            Write-Log "Importing task from: $($taskFile.FullName)"
            try {
                Register-ScheduledTask -Xml (Get-Content $taskFile.FullName | Out-String) -TaskName $taskFile.BaseName -Force | Out-Null
                Write-SystemMessage -msg1 "- Successfully imported task:" -msg2 "$($taskFile.BaseName)" 
                Write-Log "Successfully imported task: $($taskFile.BaseName)."
            } catch {
                Write-Log "Failed to import task ${taskFile.FullName}: $($_.Exception.Message)"
                Write-ErrorMessage -msg "Failed to import task: $($_.Exception.Message)"
            }
        }

        # Clean up the temporary folder
        Write-Log "Task repository import completed. Cleaning up..."
        Remove-Item -Path $tempFolder -Recurse -Force

        Write-SuccessMessage -msg "Task repository imported into task scheduler."
    } catch {
        Write-ErrorMessage -msg "Error importing task repository: $($_.Exception.Message)"
        Write-Log "Error importing task repository: $($_.Exception.Message)"
        return
    }
}



# Function to activate Windows
function Activate-Windows {

    try {
        $productKey = Get-ConfigValue -section "Activation" -key "ProductKey"
        $version = Get-ConfigValue -section "Activation" -key "Version"

        if ($productKey -and $version) {
            Write-SystemMessage -title "Activating Windows"
            Write-SystemMessage -msg1 "- Activating Windows with product key: " -msg2 $productKey
            Write-Log "Activating Windows with product key: $productKey and version: $version"
            slmgr.vbs /ipk $productKey
            slmgr.vbs /ato
            Write-Log "Windows activated successfully."
            Write-SystemMessage -msg1 "- Windows activated successfully." -msg1Color "Green"
            Write-SuccessMessage -msg "Windows activation completed."
        } else {
            Write-Log "Windows activation not performed. Missing configuration."
        }
    } catch {
        Write-ErrorMessage -msg "Error activating Windows: $($_.Exception.Message)"
        Write-Log "Error activating Windows: $($_.Exception.Message)"
        Return
    }
}

# Main script execution
if (-not (Test-IsAdmin)) {
    Write-Log 'Please run as administrator!'
    exit 5
}

try {
    $configFile = Get-ConfigFile -configFile $configFile
    Write-Log "Loading configuration file: $configFile"
    $config = Read-ConfigFile -path $configFile
    Write-Log "Configuration file loaded successfully."
} catch {
    Write-Log "Error loading configuration file: $($_.Exception.Message)"
    exit 3
}

# Execute functions
# Main script execution
Clear-Host
Set-SystemCheckpoint
Set-ComputerName
Set-EnvironmentVariables
Set-Locale
Set-DisableOneDrive
Set-DisableCopilot
Set-PowerSettings
Set-SystemTimezone
Set-TaskbarFeatures
Set-PrivacySettings
Set-Tweaks
Set-ThemeSettings
Set-SecuritySettings
Set-WindowsUpdates
Set-Services
Set-Bitlocker
Install-Fonts
Install-WingetApps 
Install-ChocolateyApps
Install-GCPW
Install-ChromeEnterprise
Install-GoogleDrive
Install-Office
Add-RegistryEntries
Remove-RegistryEntries
Import-TaskRepository
Import-Tasks
Activate-Windows


# Remove the configuration file if it was downloaded
if ($configFile -match [regex]::Escape("$env:TEMP\config.ini")) {
    Remove-Item -Path $configFile -Force -ErrorAction SilentlyContinue
    Write-Log "Temporary configuration file removed."
}

$ProgressPreference = 'Continue'
Write-Log "System configuration completed successfully."
Write-SystemMessage "System configuration completed successfully."
