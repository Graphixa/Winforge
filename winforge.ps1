#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows configuration deployment tool using XML configurations.
.DESCRIPTION
    WinforgeXML automates Windows system configuration using XML-based configuration files.
    Supports local and remote configurations with schema validation.

.PARAMETER ConfigPath
    Path to the configuration file (local .config file or URL)
.PARAMETER LogPath
    Optional custom path for log file

.EXAMPLE
    .\winforge.ps1 -ConfigPath "fresh-install.config"
.EXAMPLE
    .\winforge.ps1 -ConfigPath "https://example.com/myconfig.config" -LogPath "C:\Logs\winforge.log"

.NOTES
    Version: 1.3
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:SystemDrive\Winforge.log"
)

# Script Variables
$script:logFile = $LogPath
$script:configXML = $null
$script:schemaPath = "https://raw.githubusercontent.com/Graphixa/WinforgeX/main/schema.xsd"
$script:restartRequired = $false
$script:tempFiles = @()


# Ensure console output works in remote sessions
$VerbosePreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'Continue'

# Initialize Error Handling
$ErrorActionPreference = "Stop"

# HELPER FUNCTIONS
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $script:logFile -Value $logMessage
    

}

<#
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
        $msg2color = 'White',

        [Parameter()]
        $NoNewline
    )
    
    
    if ($PSBoundParameters.ContainsKey('title')) {
        Write-Host
        Write-Host " $title ".ToUpper() -ForegroundColor White -BackgroundColor $titleColor 
        Write-Host
    }
    
    if ($PSBoundParameters.ContainsKey('msg1') -and $PSBoundParameters.ContainsKey('NoNewline') -and $PSBoundParameters.ContainsKey('msg2')) {
        Write-Host "$msg1" -ForegroundColor $msg1Color -NoNewline; Write-Host "$msg2" -ForegroundColor $msg2color -NoNewline
        return
    }

    if ($PSBoundParameters.ContainsKey('msg1') -and $PSBoundParameters.ContainsKey('NoNewline')){
        Write-Host "$msg1" -ForegroundColor $msg1Color -NoNewline
        return
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
#>

function Write-SystemMessage {
    param (
        [Parameter()]
        [string]$Title,
  
        [Parameter()]
        [string]$Message,

        [Parameter()]
        [string]$Value,

        [Parameter()]
        [switch]$StartOperation,

        [Parameter()]
        [ValidateSet('Success', 'Failed', 'Warning', 'Info')]
        [string]$Status,

        [Parameter()]
        [string]$ErrorMessage
    )
    
    # Handle Title Block
    if ($Title) {
        Write-Host
        Write-Host " $Title ".ToUpper() -ForegroundColor White -BackgroundColor DarkMagenta
        Write-Host
        return
    }

    # Handle Message (without status)
    if ($Message -and -not $StartOperation -and -not $Status) {
        Write-Host "- $Message" -ForegroundColor Cyan
        if ($Value) {
            Write-Host ": $Value" -ForegroundColor White
        }
        return
    }

    # Start of operation
    if ($StartOperation) {
        Write-Host -NoNewline "- $Message" -ForegroundColor Cyan
        if ($Value) {
            Write-Host -NoNewline ": $Value" -ForegroundColor White
        }
        return
    }

    # Status update (end of operation)
    if ($Status) {
        switch ($Status) {
            'Success' { 
                Write-Host " - Success" -ForegroundColor Green 
            }
            'Failed' { 
                if ($ErrorMessage) {
                    Write-Host " - Failed: $ErrorMessage" -ForegroundColor Red
                } else {
                    Write-Host " - Failed" -ForegroundColor Red
                }
            }
            'Warning' { 
                Write-Host " - Warning" -ForegroundColor Yellow 
            }
            'Info' { 
                Write-Host " - Info" -ForegroundColor Gray 
            }
        }
    }
}

function Write-ErrorMessage {
    param (
      [Parameter()]
      $msg = "ERROR",
  
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
      $msg = "SUCCESS",
  
      [Parameter()]
      $msgColor = 'Green'
    )
  
    Write-Host
    Write-Host "Success: $msg " -ForegroundColor $msgColor -BackgroundColor Black
    Write-Host
  }

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ConfigSchema {
    param (
        [Parameter(Mandatory = $true)]
        [xml]$Xml
    )
    
    try {
        Write-Log "Validating configuration schema..."
        
        # Download schema if it's a URL
        if ($script:schemaPath -match '^https?://') {
            $tempSchemaPath = Join-Path $env:TEMP "winforge_schema.xsd"
            Write-Log "Downloading schema to: $tempSchemaPath"
            Invoke-WebRequest -Uri $script:schemaPath -OutFile $tempSchemaPath
            $script:tempFiles += $tempSchemaPath
            $schemaPath = $tempSchemaPath
        } else {
            $schemaPath = $script:schemaPath
        }

        # Verify schema file exists
        if (-not (Test-Path $schemaPath)) {
            throw "Schema file not found at: $schemaPath"
        }

        # Load and validate schema
        $schemaReader = New-Object System.Xml.XmlTextReader $schemaPath
        try {
        $schema = [System.Xml.Schema.XmlSchema]::Read($schemaReader, {
            param($sender, $e)
            Write-Log "Schema Load Error: $($e.Message)" -Level Error
        })
        
        if ($null -eq $schema) {
            throw "Failed to load schema"
        }

        $Xml.Schemas.Add($schema) | Out-Null
        
        $validationErrors = @()
        $Xml.Validate({
            param($sender, $e)
            $validationErrors += $e
                Write-Log "Configuration Validation Error: $($e.Message)" -Level Error
            Write-Log "Line: $($e.Exception.LineNumber), Position: $($e.Exception.LinePosition)" -Level Error
        })

        if ($validationErrors.Count -gt 0) {
                throw "Configuration validation failed with $($validationErrors.Count) errors"
        }

        return $true
        }
        finally {
            $schemaReader.Close()
        }
    }
    catch {
        Write-Log "Schema validation error: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Test-EncryptedConfig {
    param ([string]$FilePath)
    try {
        $content = Get-Content $FilePath -Raw
        $package = $content | ConvertFrom-Json
        return ($null -ne $package.Salt -and $null -ne $package.Data -and $null -ne $package.IV)
    }
    catch { return $false }
}

function Convert-SecureConfig {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [bool]$IsEncrypting,
        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    try {
        # Verify file exists
        if (-not (Test-Path $FilePath)) {
            throw "File not found: $FilePath"
        }

        # Get file content
        $configContent = Get-Content $FilePath -Raw

        # Generate output path (keep .config extension)
        $outputPath = $FilePath

        if ($IsEncrypting) {
            # Check if already encrypted
            if (Test-EncryptedConfig -FilePath $FilePath) {
                throw "File is already encrypted. Decrypt it first if you want to re-encrypt."
            }

            # Generate unique random salt
            $salt = New-Object byte[] 32
            $rng  = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
            try {
                $rng.GetBytes($salt)
            }
            finally {
                $rng.Dispose()
            }

            # Create key and IV
            $rfc = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 1000)
            try {
                $key = $rfc.GetBytes(32) # 256 bits
                $iv  = $rfc.GetBytes(16) # 128 bits

                # Convert content to bytes
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($configContent)

                # Create AES encryption object
                $aes = [System.Security.Cryptography.Aes]::Create()
                try {
                    $aes.Key     = $key
                    $aes.IV      = $iv
                    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
                    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

                    # Create encryptor and encrypt
                    $encryptor = $aes.CreateEncryptor()
                    try {
                        $encrypted = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
                    }
                    finally {
                        $encryptor.Dispose()
                    }
                    
                    # Create final encrypted package with salt
                    $package = @{
                        Salt = [Convert]::ToBase64String($salt)
                        Data = [Convert]::ToBase64String($encrypted)
                        IV   = [Convert]::ToBase64String($iv)
                    } | ConvertTo-Json
                    
                    # Save encrypted content
                    $package | Set-Content $outputPath
                    Write-Host "File encrypted successfully to: $outputPath"
                    
                    return $true  # Explicitly return $true on success
                }
                finally {
                    $aes.Dispose()
                    # Securely clear sensitive data from memory
                    for ($i = 0; $i -lt $key.Length; $i++) { $key[$i] = 0 }
                    for ($i = 0; $i -lt $iv.Length;  $i++) { $iv[$i]  = 0 }
                }
            }
            finally {
                $rfc.Dispose()
            }
        }
        else {
            try {
                Write-Host "Attempting to decrypt file..."
                
                # Parse the encrypted package
                $package   = Get-Content $FilePath -Raw | ConvertFrom-Json
                $salt      = [Convert]::FromBase64String($package.Salt)
                $encrypted = [Convert]::FromBase64String($package.Data)
                $iv        = [Convert]::FromBase64String($package.IV)

                # Recreate key from password and stored salt
                $rfc = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 1000)
                try {
                    $key = $rfc.GetBytes(32)

                    # Create AES decryption object
                    $aes = [System.Security.Cryptography.Aes]::Create()
                    try {
                        $aes.Key     = $key
                        $aes.IV      = $iv
                        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
                        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

                        # Create decryptor and decrypt
                        $decryptor = $aes.CreateDecryptor()
                        try {
                            $decrypted = $decryptor.TransformFinalBlock($encrypted, 0, $encrypted.Length)
                        }
                        catch {
                            throw "Incorrect password. Please try again with the correct password."
                        }
                        finally {
                            $decryptor.Dispose()
                        }
                        
                        # Convert back to string
                        $decryptedText = [System.Text.Encoding]::UTF8.GetString($decrypted)
                        
                        # Save decrypted content
                        $decryptedText | Set-Content $outputPath -Encoding UTF8
                        Write-Host "File decrypted successfully to: $outputPath"

                        return $true  # Explicitly return $true on success
                    }
                    finally {
                        $aes.Dispose()
                        # Securely clear sensitive data from memory
                        for ($i = 0; $i -lt $key.Length; $i++) { $key[$i] = 0 }
                    }
                }
                finally {
                    $rfc.Dispose()
                }
            }
            catch {
                throw $_.Exception.Message
            }
        }
    }
    catch {
        throw "Error processing file: $($_.Exception.Message)"
    }
}

function Get-WinforgeConfig {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    try {
        # Handle remote configurations
        if ($Path -match '^https?://') {
            # Check if URL is a Google Drive link
            if ($Path -match "drive\.google\.com") {
                $Path = Convert-GoogleDriveLink -Url $Path
            }
            Write-Log "Downloading configuration from: $Path"
            $tempPath = Join-Path $env:TEMP "winforge.config"
            $script:tempFiles += $tempPath
            Invoke-WebRequest -Uri $Path -OutFile $tempPath
            $Path = $tempPath
        }
        
       # Write-SystemMessage -Title "Configuration" -msg1 "Loading configuration file..."
       Write-SystemMessage -Title "Configuration" -Message "Loading configuration file..." -StartOperation
        
        # Check if file exists
        if (-not (Test-Path $Path)) {
            throw "Configuration file not found: $Path"
        }
        
        # Check if file is encrypted
        $isEncrypted = Test-EncryptedConfig -FilePath $Path
        if ($isEncrypted) {
            Write-SystemMessage -Title "Encrypted Configuration" -Message "Configuration is encrypted. Please enter the password to decrypt it." -StartOperation
            
            $maxAttempts = 5
            $attempt = 1
            $decrypted = $false

            while ($attempt -le $maxAttempts -and -not $decrypted) {
                if ($attempt -gt 1) {
                    Write-SystemMessage -Message "Incorrect password." -Value "Attempts remaining: $($maxAttempts - $attempt + 1)" -Status Warning
                }

                $password = Read-Host -AsSecureString "Password"
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
                $passwordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                
                # Check for empty password
                if ([string]::IsNullOrWhiteSpace($passwordText)) {
                    $attempt++
                    Write-SystemMessage -Message "Password cannot be empty." -Value "Attempts remaining: $($maxAttempts - $attempt + 1)" -Status Warning
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                    Remove-Variable -Name passwordText -ErrorAction SilentlyContinue
                    continue
                }
                
                try {
                    $decryptResult = Convert-SecureConfig -FilePath $Path -IsEncrypting $false -Password $passwordText 2>$null
                    if ($decryptResult) {
                        Write-SystemMessage -Message "Configuration decrypted successfully." -Status Success
                        $decrypted = $true
                    }
                    else {
                        $attempt++
                        Write-SystemMessage -Message "Incorrect password." -Value "Attempts remaining: $($maxAttempts - $attempt + 1)" -Status Warning
                    }
                }
                catch {
                    # Decryption failed for this attempt; just log & increment
                    Write-Log "Decryption error on attempt $attempt of ${maxAttempts}: $($_.Exception.Message)" -Level Error
                    $attempt++
                    if ($attempt -gt $maxAttempts) {
                        throw "Maximum password attempts reached. Exiting script."
                    }
                }
                finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                    Remove-Variable -Name passwordText -ErrorAction SilentlyContinue
                }
            }

            if (-not $decrypted) {
                throw "Failed to decrypt configuration after $maxAttempts attempts."
            }
        }
        
        # Now that we've decrypted in place, $Path is a plain XML file.
        try {
        [xml]$config = Get-Content -Path $Path
            
            # Validate XML against schema
            if (-not (Test-ConfigSchema -Xml $config)) {
                throw "Configuration failed schema validation"
            }
        
        return $config.WinforgeConfig
        }
        catch [System.Xml.XmlException] {
            throw "Invalid XML in configuration file: $($_.Exception.Message)"
        }
    }
    catch {
        Write-Log "Failed to load configuration: $($_.Exception.Message)" -Level Error
        
        # If it's a "max attempts" or "failed to decrypt," rethrow so the script can exit. 
        if ($_.Exception.Message -match "Maximum password attempts reached" -or 
            $_.Exception.Message -match "Failed to decrypt configuration after") {
        throw
        }
        else {
            return $null
        }
    }
}

function Convert-GoogleDriveLink {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Url
    )

    try {
        # Check if URL is a Google Drive link
        if ($Url -match "drive\.google\.com") {
            # Extract file ID using regex
            $fileId = if ($Url -match "(?:id=|/d/)([^/&\?]+)") {
                $matches[1]
            } else {
                Write-Log "Could not extract file ID from Google Drive URL" -Level Error
                return $Url
            }

            # Check if already a direct download link
            if ($Url -match "export=download") {
                Write-Log "URL is already a direct download link" -Level Info
                return $Url
            }

            # Convert to direct download link
            $directUrl = "https://drive.google.com/uc?export=download&id=$fileId"
            Write-Log "Converted Google Drive link to direct download URL" -Level Info
            return $directUrl
        }

        # Return original URL if not a Google Drive link
        return $Url
    }
    catch {
        Write-Log "Error converting Google Drive link: $($_.Exception.Message)" -Level Error
        return $Url
    }
}

function Remove-TempFiles {
    foreach ($file in $script:tempFiles) {
        if (Test-Path $file) {
            Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
        }
    }
}

function Set-RegistryModification {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("add", "remove")]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter()]
        [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "QWord")]
        [string]$Type = "String",

        [Parameter()]
        [object]$Value
    )
    
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        if ($Action -eq 'add') {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force | Out-Null
        }
        elseif ($Action -eq 'remove') {
            Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue | Out-Null
        }
        else {
            throw "Invalid action: $Action"
        }

        return $true
    }
    catch {
        Write-Log "Registry modification failed: $($_.Exception.Message)" -Level Error
        return $false
    }
}

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

function Set-SystemCheckpoint {
    try {
        # Check if System Restore is enabled
        $srEnabled = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if (-not $srEnabled) {
            Write-Log "System Restore is not enabled. Attempting to enable..." -Level Warning
            Enable-ComputerRestore -Drive "$env:systemdrive" -ErrorAction Stop | Out-Null
            Write-Log "System Restore enabled successfully"
        }

        # Check available disk space (minimum 1GB recommended)
        $systemDrive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$env:systemdrive'"
        if ($systemDrive.FreeSpace -lt 1GB) {
            Write-Log "Insufficient disk space for system restore point" -Level Error
            Write-SystemMessage -Status Failed -ErrorMessage "Insufficient disk space for system restore point"
            return $false
        }

        $date = Get-Date -Format "dd/MM/yyyy"
        $time = Get-Date -Format "HH:mm:ss"
        $snapshotName = "Winforge - $date - $time"
        
        Write-Log "Creating system restore point. Snapshot Name: $snapshotName"
        Write-SystemMessage -Title "Creating System Restore Point" -Message "Snapshot Name:" -Value $snapshotName -StartOperation
        Checkpoint-Computer -Description $snapshotName -RestorePointType "MODIFY_SETTINGS" -Verbose
        Write-SystemMessage -Status Success
        
        Write-Log "System restore point created successfully."
        return $true
    }
    catch {
        Write-Log "Error creating system restore point: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -Status Failed -ErrorMessage $_.Exception.Message
        return $false
    }
}


# CONFIGURATION FUNCTIONS
function Set-SystemConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$SystemConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring System Settings"
        $success = $true

        # Computer Name
        if ($SystemConfig.ComputerName) {
            try {
                Write-SystemMessage -Message "Setting computer name to:" -Value $SystemConfig.ComputerName -StartOperation
                $currentName = $env:COMPUTERNAME
                if ($currentName -ne $SystemConfig.ComputerName) {
                    Write-Log "Setting computer name to: $($SystemConfig.ComputerName)"
                    Rename-Computer -NewName $SystemConfig.ComputerName -Force
                    $script:restartRequired = $true
                    Write-SystemMessage -Status Success
                } else {
                    Write-Log "Computer name is already set to: $($SystemConfig.ComputerName)" -Level Warning
                    Write-SystemMessage -Status Warning
                }
            }
            catch {
                Write-Log "Error setting computer name: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -Status Failed -ErrorMessage $_.Exception.Message
                $success = $false
            }
        }

        # Locale and Timezone
        if ($SystemConfig.Locale) {
            Write-SystemMessage -msg1 "- Setting system locale to: " -msg2 $SystemConfig.Locale -NoNewline
            Write-Log "Setting system locale to: $($SystemConfig.Locale)"
            
            try {
                # Validate locale is supported
                if (Get-WinUserLanguageList | Where-Object { $_.LanguageTag -eq $SystemConfig.Locale }) {
                    Set-WinUILanguageOverride -Language $SystemConfig.Locale
                    Set-WinSystemLocale -SystemLocale $SystemConfig.Locale
                    Set-WinUserLanguageList $SystemConfig.Locale -Force
                    Set-Culture -CultureInfo $SystemConfig.Locale
                    
                    $script:restartRequired = $true
                    Write-SuccessMessage -msg "System locale set successfully"
                }
                else {
                    Write-Log "Invalid or unsupported locale: $($SystemConfig.Locale)" -Level Warning
                    Write-ErrorMessage -msg "Invalid or unsupported locale: $($SystemConfig.Locale)"
                }
            }
            catch {
                Write-Log "Error setting system locale: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set system locale"
            }
        }

        if ($SystemConfig.Timezone) {
            $currentTZ = (Get-TimeZone).Id
            if ($currentTZ -ne $SystemConfig.Timezone) {
                Write-Log "Setting timezone to: $($SystemConfig.Timezone)"
                Write-SystemMessage -msg1 "- Setting timezone to: " -msg2 $SystemConfig.Timezone
                try {
                    Set-TimeZone -Id $SystemConfig.Timezone
                    $newTZ = (Get-TimeZone).Id
                    if ($newTZ -eq $SystemConfig.Timezone) {
                        Write-SuccessMessage -msg "Timezone set successfully to: $($SystemConfig.Timezone)"
                    }
                    else {
                        Write-Log "Failed to set timezone to: $($SystemConfig.Timezone)" -Level Warning
                        Write-ErrorMessage -msg "Failed to set timezone"
                    }
                }
                catch {
                    Write-Log "Error setting timezone: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to set timezone"
                }
            }
            else {
                Write-Log "Timezone is already set to: $($SystemConfig.Timezone)"
                Write-SystemMessage -msg1 "- Timezone already set to: " -msg2 $SystemConfig.Timezone -msg1Color "Cyan"
            }
        }

        # Remote Desktop
        if ($SystemConfig.EnableRemoteDesktop -eq 'true') {
            Write-Log "Enabling Remote Desktop..."
            Write-SystemMessage -msg1 "- Enabling Remote Desktop..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
                Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
                Write-SuccessMessage -msg "Remote Desktop enabled"
            }
            catch {
                Write-Log "Failed to enable Remote Desktop: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable Remote Desktop"
            }
        }
        elseif ($SystemConfig.EnableRemoteDesktop -eq 'false') {
            Write-Log "Disabling Remote Desktop..."
            Write-SystemMessage -msg1 "- Disabling Remote Desktop..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
                Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
                Write-SuccessMessage -msg "Remote Desktop disabled"
            }
            catch {
                Write-Log "Failed to disable Remote Desktop: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Remote Desktop"
            }
        }

        # Windows Store
        if ($SystemConfig.DisableWindowsStore -eq 'true') {
            Write-Log "Disabling Windows Store..."
            Write-SystemMessage -msg1 "- Disabling Windows Store..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Type DWord -Value 1
                Write-SuccessMessage -msg "Windows Store disabled"
            }
            catch {
                Write-Log "Failed to disable Windows Store: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Windows Store"
            }
        }
        elseif ($SystemConfig.DisableWindowsStore -eq 'false') {
            Write-Log "Enabling Windows Store..."
            Write-SystemMessage -msg1 "- Enabling Windows Store..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Type DWord -Value 0
                Write-SuccessMessage -msg "Windows Store enabled"
            }
            catch {
                Write-Log "Failed to enable Windows Store: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable Windows Store"
            }
        }

        if ($SystemConfig.DisableOneDrive -eq 'true') {
            Write-Log "Disabling OneDrive..."
            Write-SystemMessage -msg1 "- Disabling OneDrive."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
                Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
                Write-SuccessMessage -msg "OneDrive disabled."
            }
            catch {
                Write-Log "Error disabling OneDrive: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable OneDrive."
            }
        }
        elseif ($SystemConfig.DisableOneDrive -eq 'false') {
            Write-Log "Enabling OneDrive..."
            Write-SystemMessage -msg1 "- Enabling OneDrive."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 0
                Write-SuccessMessage -msg "OneDrive enabled."
            }
            catch {
                Write-Log "Error enabling OneDrive: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable OneDrive."
            }
        }

        if ($SystemConfig.DisableCopilot -eq 'true') {
            Write-Log "Disabling Windows Copilot..."
            Write-SystemMessage -msg1 "- Disabling Windows Copilot."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "CopilotEnabled" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type DWord -Value 1
                Write-SuccessMessage -msg "Windows Copilot disabled."
            }
            catch {
                Write-Log "Error disabling Windows Copilot: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Windows Copilot."
            }
        }
        elseif ($SystemConfig.DisableCopilot -eq 'false') {
            Write-Log "Enabling Windows Copilot..."
            Write-SystemMessage -msg1 "- Enabling Windows Copilot."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "CopilotEnabled" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type DWord -Value 0
                Write-SuccessMessage -msg "Windows Copilot enabled."
            }
            catch {
                Write-Log "Error enabling Windows Copilot: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable Windows Copilot."
            }
        }

        # File Explorer Settings
        if ($SystemConfig.ShowFileExtensions -eq 'true') {
            Write-SystemMessage -msg1 "- Showing file extensions..."
            Write-Log "Showing file extensions..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
                Write-SuccessMessage -msg "File extensions enabled"
            }
            catch {
                Write-Log "Failed to show file extensions: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to show file extensions"
            }
        }
        elseif ($SystemConfig.ShowFileExtensions -eq 'false') {
            Write-SystemMessage -msg1 "- Hiding file extensions..."
            Write-Log "Hiding file extensions..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1
                Write-SuccessMessage -msg "File extensions hidden"
            }
            catch {
                Write-Log "Failed to hide file extensions: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to hide file extensions"
            }
        }

        if ($SystemConfig.ShowHiddenFiles -eq 'true') {
            Write-SystemMessage -msg1 "- Showing hidden files..."
            Write-Log "Showing hidden files..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
                Write-SuccessMessage -msg "Hidden files enabled"
            }
            catch {
                Write-Log "Failed to show hidden files: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to show hidden files"
            }
        }
        elseif ($SystemConfig.ShowHiddenFiles -eq 'false') {
            Write-SystemMessage -msg1 "- Hiding hidden files..."
            Write-Log "Hiding hidden files..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 0
                Write-SuccessMessage -msg "Hidden files disabled"
            }
            catch {
                Write-Log "Failed to hide hidden files: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to hide hidden files"
            }
        }

        Write-Log "System configuration completed"
        return $success
    }
    catch {
        Write-Log "Error in system configuration: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-SecurityConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$SecurityConfig
    )
    

        try {
            Write-SystemMessage -Title "Configuring Security Settings"

            # Windows Defender
            if ($SecurityConfig.DisableDefender -eq 'true') {
                Write-SystemMessage -msg1 "- Disabling Windows Defender..."
                Write-Log "Disabling Windows Defender..."
                try {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
                    Write-SuccessMessage -msg "Windows Defender disabled"
                }
                catch {
                    Write-Log "Failed to disable Windows Defender: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to disable Windows Defender"
                }
            }
            elseif ($SecurityConfig.DisableDefender -eq 'false') {
                Write-SystemMessage -msg1 "- Enabling Windows Defender..."
                Write-Log "Enabling Windows Defender..."
                try {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 0
                    Write-SuccessMessage -msg "Windows Defender enabled"
                }
                catch {
                    Write-Log "Failed to enable Windows Defender: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to enable Windows Defender"
                }
            }

            # UAC Settings
            if ($SecurityConfig.DisableUAC -eq 'true') {
                Write-SystemMessage -msg1 "- Disabling UAC..."
                Write-Log "Disabling UAC..."
                try {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 0
                    Write-SuccessMessage -msg "UAC disabled"
                    $script:restartRequired = $true
                }
                catch {
                    Write-Log "Failed to disable UAC: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to disable UAC"
                }
            }
            elseif ($SecurityConfig.DisableUAC -eq 'false') {
                Write-SystemMessage -msg1 "- Enabling UAC..."
                Write-Log "Enabling UAC..."
                try {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 1
                    Write-SuccessMessage -msg "UAC enabled"
                    $script:restartRequired = $true
                }
                catch {
                    Write-Log "Failed to enable UAC: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to enable UAC"
                }
            }

            # UAC Level Settings
            if ($SecurityConfig.UACLevel) {
                Write-SystemMessage -msg1 "- Setting UAC level to: " -msg2 $SecurityConfig.UACLevel
                Write-Log "Setting UAC level to: $($SecurityConfig.UACLevel)"
                try {
                    $uacValue = switch ($SecurityConfig.UACLevel) {
                        "AlwaysNotify" { 2 }    # Always notify
                        "NeverNotify" { 0 }     # Never notify
                        "Default" { 5 }         # Default - Notify when apps try to make changes (no dim)
                        default {
                            Write-Log "Invalid UAC level specified: $($SecurityConfig.UACLevel). Using default." -Level Warning
                            5  # Default value
                        }
                    }
                
                    $promptValue = if ($uacValue -eq 2) { 1 } else { 0 }
                
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value $uacValue
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value $promptValue
                    Write-SuccessMessage -msg "UAC level set successfully"
                }
                catch {
                    Write-Log "Failed to set UAC level: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to set UAC level"
                }
            
            }


            # SMB1 Protocol
            if ($SecurityConfig.DisableSMB1 -eq 'true') {
                Write-SystemMessage -msg1 "- Disabling SMB1 protocol..."
                Write-Log "Disabling SMB1 protocol..."
                try {
                    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
                    $script:restartRequired = $true
                    Write-SuccessMessage -msg "SMB1 protocol disabled"
                }
                catch {
                    Write-Log "Failed to disable SMB1 protocol: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to disable SMB1 protocol"
                }
            }
            elseif ($SecurityConfig.DisableSMB1 -eq 'false') {
                Write-SystemMessage -msg1 "- Enabling SMB1 protocol..."
                Write-Log "Enabling SMB1 protocol..."
                try {
                    Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
                    $script:restartRequired = $true
                    Write-SuccessMessage -msg "SMB1 protocol enabled"
                }
                catch {
                    Write-Log "Failed to enable SMB1 protocol: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to enable SMB1 protocol"
                }
            }

            # AutoPlay
            if ($SecurityConfig.DisableAutoPlay -eq 'true') {
                Write-SystemMessage -msg1 "- Disabling AutoPlay..."
                Write-Log "Disabling AutoPlay..."
                try {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
                    Write-SuccessMessage -msg "AutoPlay disabled"
                }
                catch {
                    Write-Log "Failed to disable AutoPlay: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to disable AutoPlay"
                }
            }
            elseif ($SecurityConfig.DisableAutoPlay -eq 'false') {
                Write-SystemMessage -msg1 "- Enabling AutoPlay..."
                Write-Log "Enabling AutoPlay..."
                try {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 0
                    Write-SuccessMessage -msg "AutoPlay enabled"
                }
                catch {
                    Write-Log "Failed to enable AutoPlay: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to enable AutoPlay"
                }
            }

            # BitLocker
            if ($SecurityConfig.BitLocker.Enable -eq 'true') {
                Write-SystemMessage -msg1 "- Configuring BitLocker for drive: " -msg2 $SecurityConfig.BitLocker.Target
                Write-Log "Configuring BitLocker for drive: $($SecurityConfig.BitLocker.Target)"
                try {
                    Enable-BitLocker -MountPoint $SecurityConfig.BitLocker.Target -EncryptionMethod XtsAes256 -UsedSpaceOnly
                    Write-SuccessMessage -msg "BitLocker configured successfully"
                }
                catch {
                    Write-Log "Failed to configure BitLocker: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to configure BitLocker"
                }
            }
            elseif ($SecurityConfig.BitLocker.Enable -eq 'false') {
                Write-SystemMessage -msg1 "- Disabling BitLocker for drive: " -msg2 $SecurityConfig.BitLocker.Target
                Write-Log "Disabling BitLocker for drive: $($SecurityConfig.BitLocker.Target)"
                try {
                    Disable-BitLocker -MountPoint $SecurityConfig.BitLocker.Target
                    Write-SuccessMessage -msg "BitLocker disabled successfully"
                }
                catch {
                    Write-Log "Failed to disable BitLocker: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to disable BitLocker"
                }
            }

            Write-Log "Security configuration completed successfully"
            return $true
        }
        catch {
            Write-Log "Error configuring security settings: $($_.Exception.Message)" -Level Error
            Write-ErrorMessage -msg "Failed to configure security settings"
            return $false
        }
    }


function Set-PrivacyConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$PrivacyConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Privacy Settings"

        # Telemetry
        if ($PrivacyConfig.DisableTelemetry -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling telemetry..."
            Write-Log "Disabling telemetry..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
                Write-SuccessMessage -msg "Telemetry disabled"
            } catch {
                Write-Log "Failed to disable telemetry: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable telemetry"
            }
        } elseif ($PrivacyConfig.DisableTelemetry -eq 'false') {
            Write-SystemMessage -msg1 "- Enabling telemetry..."
            Write-Log "Enabling telemetry..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 1
                Write-SuccessMessage -msg "Telemetry enabled"
            } catch {
                Write-Log "Failed to enable telemetry: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable telemetry"
            }
        }

        # DiagTrack
        if ($PrivacyConfig.DisableDiagTrack -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling diagnostic tracking..."
            Write-Log "Disabling diagnostic tracking..."
            try {
                Stop-Service "DiagTrack" -Force
                Set-Service "DiagTrack" -StartupType Disabled
                Write-SuccessMessage -msg "Diagnostic tracking disabled"
            } catch {
                Write-Log "Failed to disable diagnostic tracking: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable diagnostic tracking"
            }
        } elseif ($PrivacyConfig.DisableDiagTrack -eq 'false') {
            Write-SystemMessage -msg1 "- Enabling diagnostic tracking..."
            Write-Log "Enabling diagnostic tracking..."
            try {
                Set-Service "DiagTrack" -StartupType Automatic
                Start-Service "DiagTrack"
                Write-SuccessMessage -msg "Diagnostic tracking enabled"
            } catch {
                Write-Log "Failed to enable diagnostic tracking: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable diagnostic tracking"
            }
        }

        # App Privacy
        if ($PrivacyConfig.DisableAppPrivacy -eq 'true') {
            Write-SystemMessage -msg1 "- Configuring app privacy settings..."
            Write-Log "Configuring app privacy settings..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Type String -Value "Deny"
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Type String -Value "Deny"
                Write-SuccessMessage -msg "App privacy settings configured"
            } catch {
                Write-Log "Failed to configure app privacy settings: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to configure app privacy settings"
            }
        } elseif ($PrivacyConfig.DisableAppPrivacy -eq 'false') {
            Write-SystemMessage -msg1 "- Enabling app privacy settings..."
            Write-Log "Enabling app privacy settings..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Allow"
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Type String -Value "Allow"
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Type String -Value "Allow"
                Write-SuccessMessage -msg "App privacy settings enabled"
            } catch {
                Write-Log "Failed to enable app privacy settings: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable app privacy settings"
            }
        }

        # Start Menu Tracking
        if ($PrivacyConfig.DisableStartMenuTracking -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling Start Menu tracking..."
            Write-Log "Disabling Start Menu tracking..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
                Write-SuccessMessage -msg "Start Menu tracking disabled"
            } catch {
                Write-Log "Failed to disable Start Menu tracking: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Start Menu tracking"
            }
        } elseif ($PrivacyConfig.DisableStartMenuTracking -eq 'false') {
            Write-SystemMessage -msg1 "- Enabling Start Menu tracking..."
            Write-Log "Enabling Start Menu tracking..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 0
                Write-SuccessMessage -msg "Start Menu tracking enabled"
            } catch {
                Write-Log "Failed to enable Start Menu tracking: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable Start Menu tracking"
            }
        }

        # Activity History
        if ($PrivacyConfig.DisableActivityHistory -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling Activity History..."
            Write-Log "Disabling Activity History..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
                Write-SuccessMessage -msg "Activity History disabled"
            } catch {
                Write-Log "Failed to disable Activity History: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Activity History"
            }
        } elseif ($PrivacyConfig.DisableActivityHistory -eq 'false') {
            Write-SystemMessage -msg1 "- Enabling Activity History..."
            Write-Log "Enabling Activity History..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 1
                Write-SuccessMessage -msg "Activity History enabled"
            } catch {
                Write-Log "Failed to enable Activity History: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable Activity History"
            }
        }

        # Clipboard Data Collection
        if ($PrivacyConfig.DisableClipboardDataCollection -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling Clipboard data collection..."
            Write-Log "Disabling Clipboard data collection..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 0
                Write-SuccessMessage -msg "Clipboard data collection disabled"
            } catch {
                Write-Log "Failed to disable Clipboard data collection: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Clipboard data collection"
            }
        } elseif ($PrivacyConfig.DisableClipboardDataCollection -eq 'false') {
            Write-SystemMessage -msg1 "- Enabling Clipboard data collection..."
            Write-Log "Enabling Clipboard data collection..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 1
                Write-SuccessMessage -msg "Clipboard data collection enabled"
            } catch {
                Write-Log "Failed to enable Clipboard data collection: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable Clipboard data collection"
            }
        } 

        # Start Menu Suggestions
        if ($PrivacyConfig.DisableStartMenuSuggestions -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling Start Menu suggestions..."
            Write-Log "Disabling Start Menu suggestions..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
                Write-SuccessMessage -msg "Start Menu suggestions disabled"
            } catch {
                Write-Log "Failed to disable Start Menu suggestions: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Start Menu suggestions"
            }
        } elseif ($PrivacyConfig.DisableStartMenuSuggestions -eq 'false') {
            Write-SystemMessage -msg1 "- Enabling Start Menu suggestions..."
            Write-Log "Enabling Start Menu suggestions..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 1
                Write-SuccessMessage -msg "Start Menu suggestions enabled"
            } catch {
                Write-Log "Failed to enable Start Menu suggestions: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable Start Menu suggestions"
            }
        }

        Write-Log "Privacy configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring privacy settings: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure privacy settings"
        return $false
    }
}

function Install-Applications {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$AppConfig
    )
    
    try {
        Write-SystemMessage -Title "Installing Applications"

        # Package Manager Selection
        $packageManager = $AppConfig.PackageManager

        # Chocolatey Apps
        if ($packageManager -eq "Chocolatey" -and $AppConfig.ChocolateyApps) {
            Write-SystemMessage -msg1 "- Checking Chocolatey is installed..."
            Write-Log "Checking Chocolatey is installed..."

            # Install Chocolatey if not present
            if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                Write-SystemMessage -msg1 "- Installing Chocolatey package manager..."
                Write-Log "Installing Chocolatey package manager..."
                try {
                    Set-ExecutionPolicy Bypass -Scope Process -Force
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                    Write-SuccessMessage -msg "Chocolatey installed successfully"
                } catch {
                    Write-Log "Failed to install Chocolatey: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to install Chocolatey"
                    return $false
                }
            }

            # Install Chocolatey Apps
            foreach ($app in $AppConfig.ChocolateyApps.App) {
                Write-SystemMessage -msg1 "- Installing: " -msg2 $app
                Write-Log "Installing $app..."
                try {
                    if ($app.Version) {
                        choco install $app --version $app.Version -y
                    } else {
                        choco install $app -y
                    }
                    Write-SuccessMessage -msg "$app installed successfully"
                } catch {
                    Write-Log "Failed to install $app : $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to install $app"
                }
            }
        }

        # Winget Apps
        if ($packageManager -eq "Winget" -and $AppConfig.WingetApps) {
            Write-SystemMessage -msg1 "- Checking Winget installation..."
            Write-Log "Checking Winget installation..."

            # Check if Winget is available
            if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                Write-Log "Winget is not installed" -Level Error
                Write-ErrorMessage -msg "Winget is not installed. Please install Windows App Installer"
                return $false
            }

            # Reset Winget sources and accept agreements
            Write-SystemMessage -msg1 "- Resetting Winget sources..."
            Write-Log "Resetting Winget sources..."
            try {
                winget source reset --force
                Add-AppxPackage -Path "https://cdn.winget.microsoft.com/cache/source.msix"
                Write-SuccessMessage -msg "Winget sources reset successfully"
            } catch {
                Write-Log "Failed to reset Winget sources: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to reset Winget sources"
            }

            # Install Winget Apps
            foreach ($app in $AppConfig.WingetApps.App) {
                Write-SystemMessage -msg1 "- Installing: " -msg2 $app.ID
                Write-Log "Installing $($app.ID)..."
                try {
                    if ($app.Version) {
                        winget install $app.ID --version $app.Version --accept-source-agreements --accept-package-agreements
                    } else {
                        winget install $app.ID --accept-source-agreements --accept-package-agreements
                    }
                    Write-SuccessMessage -msg "$($app.ID) installed successfully"
                } catch {
                    Write-Log "Failed to install $($app.ID): $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to install $($app.ID)"
                }
            }
        }

        Write-Log "Application installation completed successfully"
        return $true
    }
    catch {
        Write-Log "Error installing applications: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to install applications"
        return $false
    }
}

function Set-EnvironmentVariables {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$EnvConfig
    )
    
    try {
        Write-SystemMessage -Title "Setting Environment Variables"
        foreach ($variable in $EnvConfig.ChildNodes) {
            [System.Environment]::SetEnvironmentVariable($variable.Name, $variable.InnerText, [System.EnvironmentVariableTarget]::Machine)
        }
        return $true
    }
    catch {
        Write-Log "Error setting environment variables: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-WindowsActivation {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$ActivationConfig
    )
    
    try {
        Write-SystemMessage -Title "Windows Activation"
        $productKey = $ActivationConfig.ProductKey
        $version = $ActivationConfig.Version
        
        # Install product key
        if ($productKey) {
            Write-Log "Installing product key..."
            slmgr.vbs /ipk $productKey
            Start-Sleep -Seconds 2
            slmgr.vbs /ato
        }
        return $true
    }
    catch {
        Write-Log "Error activating Windows: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-WindowsUpdateConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$UpdateConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Windows Update"
        
        # Auto Update Settings
        if ($UpdateConfig.NoAutoUpdate) {
            Write-SystemMessage -msg1 "- Configuring automatic updates..."
            Write-Log "Setting automatic updates to: $($UpdateConfig.NoAutoUpdate)"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value ([int]$UpdateConfig.NoAutoUpdate)
                Write-SuccessMessage -msg "Automatic updates configured"
            } catch {
                Write-Log "Failed to configure automatic updates: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to configure automatic updates"
            }
        }

        # Update Options (2=Notify, 3=Auto DL, 4=Auto DL and Install)
        if ($UpdateConfig.AUOptions) {
            Write-SystemMessage -msg1 "- Setting update behavior..."
            Write-Log "Setting update options to: $($UpdateConfig.AUOptions)"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value $UpdateConfig.AUOptions
                Write-SuccessMessage -msg "Update behavior configured"
            } catch {
                Write-Log "Failed to set update options: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set update options"
            }
        }

        # Schedule Settings
        if ($UpdateConfig.ScheduledInstallDay -and $UpdateConfig.ScheduledInstallTime) {
            Write-SystemMessage -msg1 "- Configuring update schedule..."
            Write-Log "Setting update schedule - Day: $($UpdateConfig.ScheduledInstallDay), Time: $($UpdateConfig.ScheduledInstallTime)"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Type DWord -Value $UpdateConfig.ScheduledInstallDay
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Type DWord -Value $UpdateConfig.ScheduledInstallTime
                Write-SuccessMessage -msg "Update schedule configured"
            } catch {
                Write-Log "Failed to set update schedule: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set update schedule"
            }
        }

        # Auto Install Minor Updates
        if ($UpdateConfig.AutoInstallMinorUpdates -eq 'true') {
            Write-SystemMessage -msg1 "- Enabling automatic minor updates..."
            Write-Log "Enabling automatic minor updates..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutoInstallMinorUpdates" -Type DWord -Value 1
                Write-SuccessMessage -msg "Automatic minor updates enabled"
            } catch {
                Write-Log "Failed to enable automatic minor updates: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable automatic minor updates"
            }
        } elseif ($UpdateConfig.AutoInstallMinorUpdates -eq 'false') {
            Write-SystemMessage -msg1 "- Disabling automatic minor updates..."
            Write-Log "Disabling automatic minor updates..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutoInstallMinorUpdates" -Type DWord -Value 0
                Write-SuccessMessage -msg "Automatic minor updates disabled"
            } catch {
                Write-Log "Failed to disable automatic minor updates: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable automatic minor updates"
            }
        }

        Write-Log "Windows Update configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring Windows Update: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure Windows Update"
        return $false
    }
}

function Set-ScheduledTasksConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$TasksConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Scheduled Tasks"

        foreach ($task in $TasksConfig.Task) {
            Write-SystemMessage -msg1 "- Importing task: " -msg2 $task.Name
            Write-Log "Importing task: $($task.Name)"
            
            try {
                # Handle remote or local task XML
                if ($task.Path -match '^https?://') {
                    $tempPath = Join-Path $env:TEMP "$($task.Name).xml"
                    $script:tempFiles += $tempPath
                    Invoke-WebRequest -Uri $task.Path -OutFile $tempPath
                    $taskPath = $tempPath
                } else {
                    $taskPath = Join-Path $PSScriptRoot $task.Path
                }

                # Register the task
                if (Test-Path $taskPath) {
                    Register-ScheduledTask -TaskName $task.Name -Xml (Get-Content $taskPath -Raw) -Force
                    Write-Log "Task imported successfully: $($task.Name)"
                    Write-SystemMessage -msg1 "- Task imported successfully: " -msg2 $task.Name
                } else {
                    Write-Log "Task XML file not found: $taskPath" -Level Warning
                    Write-ErrorMessage -msg "Task XML file not found: $taskPath"
                }
            } catch {
                Write-Log "Failed to import task $($task.Name): $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to import task: $($task.Name)"
            }
        }

        Write-Log "Scheduled tasks configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring scheduled tasks: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure scheduled tasks"
        return $false
    }
}


# SYSTEM MODIFICATION FUNCTIONS

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

    $isFontInstalled = $InstalledFonts | Where-Object { $_.FontName -like "*$FontName*" }
    return $isFontInstalled
}

# Function to download font files from GitHub
function Get-Fonts {
    param (
        [string]$fontName,
        [string]$outputPath
    )

    try {
        $githubUrl = "https://github.com/google/fonts"
        $fontRepoUrl = "$githubUrl/tree/main/ofl/$fontName"

        if (-not (Test-Path -Path $outputPath)) {
            New-Item -ItemType Directory -Path $outputPath | Out-Null
        }

        Write-Log "Fetching font files from GitHub: $fontRepoUrl"
        $fontFilesPage = Invoke-WebRequest -Uri $fontRepoUrl -UseBasicParsing
        $fontFileLinks = $fontFilesPage.Links | Where-Object { $_.href -match "\.ttf$" -or $_.href -match "\.otf$" }

        if (-not $fontFileLinks) {
            throw "No font files found for $fontName"
        }

        foreach ($link in $fontFileLinks) {
            $fileUrl = "https://github.com" + $link.href.Replace("/blob/", "/raw/")
            $fileName = [System.IO.Path]::GetFileName($link.href)
            $outputFile = Join-Path -Path $outputPath -ChildPath $fileName

            Write-Log "Downloading $fileName"
            Invoke-WebRequest -Uri $fileUrl -OutFile $outputFile | Out-Null
            
            if (-not (Test-Path $outputFile)) {
                throw "Failed to download $fileName"
            }
        }
    }
    catch {
        Write-Log "Error downloading fonts: $($_.Exception.Message)" -Level Error
        throw
    }
}

# Function to install Google fonts from GitHub repository
function Install-Fonts {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$FontConfig
    )
    
    try {
        Write-SystemMessage -Title "Installing Fonts"
        
        $ProgressPreference = 'SilentlyContinue'
        $tempDownloadFolder = "$env:TEMP\google_fonts"
        $script:tempFiles += $tempDownloadFolder

        foreach ($fontName in $FontConfig.Font) {
            # Correct the font names for the GitHub repository
            $correctFontName = $fontName -replace "\+", ""

            # Check if the font is already installed
            if (Test-FontInstalled -FontName $correctFontName) {
                Write-Log "Font $correctFontName is already installed. Skipping..."
                Write-SystemMessage -msg1 "- $correctFontName is already installed. Skipping..." -msg1Color "Cyan"
                continue
            }

            Write-SystemMessage -msg1 "- Downloading & Installing: " -msg2 $correctFontName
            Write-Log "Downloading & Installing $correctFontName from Google Fonts GitHub repository..."

            try {
                # Download the font files
                Get-Fonts -fontName $correctFontName -outputPath $tempDownloadFolder | Out-Null

                # Install the font files
                $allFonts = Get-ChildItem -Path $tempDownloadFolder -Include *.ttf, *.otf -Recurse
                foreach ($font in $allFonts) {
                    $fontDestination = Join-Path -Path $env:windir\Fonts -ChildPath $font.Name
                    Copy-Item -Path $font.FullName -Destination $fontDestination -Force | Out-Null

                    # Register the font
                    Set-RegistryModification -Action add -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" -Name $font.BaseName -Value $font.Name -Type String
                }

                Write-Log "Font installed: $correctFontName"
                Write-SuccessMessage -msg "$correctFontName installed successfully"

            } catch {
                Write-Log "Failed to install font $correctFontName : $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to install font: $correctFontName"
                continue
            }
        }

        Write-Log "Font installation completed successfully"
        return $true
    }
    catch {
        Write-Log "Error installing fonts: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to install fonts"
        return $false
    }
    finally {
        $ProgressPreference = 'Continue'
        if (Test-Path $tempDownloadFolder) {
            Remove-Item -Path $tempDownloadFolder -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

# Function to configure the taskbar settings
function Set-TaskbarConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$TaskbarConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Taskbar Settings"

        # Taskbar Alignment (Left = 0, Center = 1)
        if ($TaskbarConfig.TaskbarAlignment) {
            Write-Log "Setting taskbar alignment to: $($TaskbarConfig.TaskbarAlignment)"
            $alignmentValue = if ($TaskbarConfig.TaskbarAlignment -eq 'Left') { 0 } else { 1 }
            Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type DWord -Value $alignmentValue
        }

        # Meet Now
        if ($TaskbarConfig.DisableMeetNow -eq 'true') {
            Write-Log "Disabling Meet Now..."
            Write-SystemMessage -msg1 "- Disabling Meet Now..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
                Write-SuccessMessage -msg "Meet Now disabled"
            } catch {
                Write-Log "Failed to disable Meet Now: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Meet Now"
            }
        } elseif ($TaskbarConfig.DisableMeetNow -eq 'false') {
            Write-Log "Enabling Meet Now..."
            Write-SystemMessage -msg1 "- Enabling Meet Now..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 0
                Write-SuccessMessage -msg "Meet Now enabled"
            } catch {
                Write-Log "Failed to enable Meet Now: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable Meet Now"
            }
        }

        # Widgets
        if ($TaskbarConfig.DisableWidgets -eq 'true') {
            Write-Log "Disabling Widgets..."
            Write-SystemMessage -msg1 "- Disabling Widgets..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 0
                Write-SuccessMessage -msg "Widgets disabled"
            } catch {
                Write-Log "Failed to disable Widgets: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Widgets"
            }
        } elseif ($TaskbarConfig.DisableWidgets -eq 'false') {
            Write-Log "Enabling Widgets..."
            Write-SystemMessage -msg1 "- Enabling Widgets..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 1
                Write-SuccessMessage -msg "Widgets enabled"
            } catch {
                Write-Log "Failed to enable Widgets: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable Widgets"
            }
        }

        # Task View
        if ($TaskbarConfig.DisableTaskView -eq 'true') {
            Write-Log "Disabling Task View button..."
            Write-SystemMessage -msg1 "- Disabling Task View button..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
                Write-SuccessMessage -msg "Task View button disabled"
            } catch {
                Write-Log "Failed to disable Task View button: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Task View button"
            }
        } elseif ($TaskbarConfig.DisableTaskView -eq 'false') {
            Write-Log "Enabling Task View button..."
            Write-SystemMessage -msg1 "- Enabling Task View button..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 1
                Write-SuccessMessage -msg "Task View button enabled"
            } catch {
                Write-Log "Failed to enable Task View button: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable Task View button"
            }
        }

        # Search
        if ($TaskbarConfig.DisableSearch -eq 'true') {
            Write-Log "Disabling Search icon..."
            Write-SystemMessage -msg1 "- Disabling Search icon..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSearchBox" -Type DWord -Value 0
                Write-SuccessMessage -msg "Search icon disabled"
            } catch {
                Write-Log "Failed to disable Search icon: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Search icon"
            }
        } elseif ($TaskbarConfig.DisableSearch -eq 'false') {
            Write-Log "Enabling Search icon..."
            Write-SystemMessage -msg1 "- Enabling Search icon..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSearchBox" -Type DWord -Value 1
                Write-SuccessMessage -msg "Search icon enabled"
            } catch {
                Write-Log "Failed to enable Search icon: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable Search icon"
            }
        }

        # Restart Explorer to apply changes
        Write-Log "Restarting Explorer to apply taskbar changes..."
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        Start-Process explorer

        Write-Log "Taskbar configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring taskbar: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Function to configure the power settings
function Set-PowerConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$PowerConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Power Settings"

        # Power Plan
        if ($PowerConfig.PowerPlan) {
            Write-SystemMessage -msg1 "- Setting power plan to: " -msg2 $PowerConfig.PowerPlan
            Write-Log "Setting power plan to: $($PowerConfig.PowerPlan)"

            $guid = switch ($PowerConfig.PowerPlan) {
                "Balanced" { "381b4222-f694-41f0-9685-ff5bb260df2e" }
                "HighPerformance" { "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" }
                "PowerSaver" { "a1841308-3541-4fab-bc81-f71556f20b4a" }
                default {
                    Write-Log "Invalid power plan specified: $($PowerConfig.PowerPlan)" -Level Warning
                    Write-ErrorMessage -msg "Invalid power plan specified"
                    return $false
                }
            }
            
            try {
                powercfg /setactive $guid
                Write-SuccessMessage -msg "Power plan set to: $($PowerConfig.PowerPlan)"
            } catch {
                Write-Log "Failed to set power plan: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set power plan"
                return $false
            }
        }

        # Sleep Settings
        if ($PowerConfig.DisableSleep -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling sleep..."
            try {
                powercfg /change standby-timeout-ac 0
                powercfg /change standby-timeout-dc 0
                Write-SuccessMessage -msg "Sleep disabled"
            } catch {
                Write-Log "Failed to disable sleep: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable sleep"
            }
        } elseif ($PowerConfig.DisableSleep -eq 'false') {
            Write-SystemMessage -msg1 "- Enabling sleep..."
            try {
                powercfg /change standby-timeout-ac 30
                powercfg /change standby-timeout-dc 30
                Write-SuccessMessage -msg "Sleep enabled"
            } catch {
                Write-Log "Failed to enable sleep: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable sleep"
            }
        }

        # Hibernate Settings
        if ($PowerConfig.DisableHibernate -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling hibernate..."
            try {
                powercfg /hibernate off
                Write-SuccessMessage -msg "Hibernate disabled"
            } catch {
                Write-Log "Failed to disable hibernate: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable hibernate"
            }
        } elseif ($PowerConfig.DisableHibernate -eq 'false') {
            Write-SystemMessage -msg1 "- Enabling hibernate..."
            try {
                powercfg /hibernate on
                Write-SuccessMessage -msg "Hibernate enabled"
            } catch {
                Write-Log "Failed to enable hibernate: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable hibernate"
            }
        }

        # Timeouts (if specified)
        if ($PowerConfig.MonitorTimeout) {
            Write-SystemMessage -msg1 "- Setting monitor timeout to: " -msg2 "$($PowerConfig.MonitorTimeout) minutes"
            powercfg /change monitor-timeout-ac $PowerConfig.MonitorTimeout
            powercfg /change monitor-timeout-dc $PowerConfig.MonitorTimeout
        }

        # Fast Startup
        if ($PowerConfig.DisableFastStartup -eq 'true') {
            Write-SystemMessage -msg1 "- Disabling fast startup..."
            Write-Log "Disabling fast startup..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
                Write-SuccessMessage -msg "Fast startup disabled"
            } catch {
                Write-Log "Failed to disable fast startup: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable fast startup"
            }
        } elseif ($PowerConfig.DisableFastStartup -eq 'false') {
            Write-SystemMessage -msg1 "- Enabling fast startup..."
            Write-Log "Enabling fast startup..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1
                Write-SuccessMessage -msg "Fast startup enabled"
            } catch {
                Write-Log "Failed to enable fast startup: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable fast startup"
            }
        }

        Write-Log "Power configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring power settings: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure power settings"
        return $false
    }
}

# Function to apply registry modifications
function Set-RegistryEntries {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$RegistryConfig
    )
    
    try {
        Write-SystemMessage -Title "Applying Registry Modifications"

        # Process registry additions
        if ($RegistryConfig.Add) {
            Write-SystemMessage -msg1 "- Processing registry additions..."
            foreach ($entry in $RegistryConfig.Add.Entry) {
                # Expand environment variables in the value
                $expandedValue = $ExecutionContext.InvokeCommand.ExpandString($entry.Value)

                Write-SystemMessage -msg1 "- Adding registry entry: " -msg2 "Path=$($entry.Path), Name=$($entry.Name)"
                Write-Log "Adding registry entry: Path=$($entry.Path), Name=$($entry.Name), Type=$($entry.Type), Value=$expandedValue"

                try {
                    if (-not (Test-Path $entry.Path)) {
                        New-Item -Path $entry.Path -Force | Out-Null
                        Write-Log "Created registry path: $($entry.Path)"
                    }

                    Set-ItemProperty -Path $entry.Path -Name $entry.Name -Value $expandedValue -Type $entry.Type -Force
                    Write-SuccessMessage -msg "Registry entry added successfully"
                }
                catch {
                    Write-Log "Failed to add registry entry: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to add registry entry: Path=$($entry.Path), Name=$($entry.Name)"
                    continue
                }
            }
        }

        # Process registry removals
        if ($RegistryConfig.Remove) {
            Write-SystemMessage -msg1 "- Processing registry removals..."
            foreach ($entry in $RegistryConfig.Remove.Entry) {
                Write-SystemMessage -msg1 "- Removing registry entry: " -msg2 "Path=$($entry.Path), Name=$($entry.Name)"
                Write-Log "Removing registry entry: Path=$($entry.Path), Name=$($entry.Name)"

                try {
                    if (Test-Path $entry.Path) {
                        Remove-ItemProperty -Path $entry.Path -Name $entry.Name -Force -ErrorAction Stop
                        Write-SuccessMessage -msg "Registry entry removed successfully"
                    }
                    else {
                        Write-Log "Registry path not found: $($entry.Path)" -Level Warning
                        Write-ErrorMessage -msg "Registry path not found"
                    }
                } catch {
                    Write-Log "Failed to remove registry entry: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to remove registry entry: Path=$($entry.Path), Name=$($entry.Name)"
                    continue
                }
            }
        }

        Write-Log "Registry modifications completed successfully"
        return $true
    }
    catch {
        Write-Log "Error modifying registry entries: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to modify registry entries"
        return $false
    }
}

# Function to configure Windows features
function Set-WindowsFeaturesConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$FeaturesConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Windows Features"

        # Get list of available Windows features
        $availableFeatures = Get-WindowsOptionalFeature -Online | Select-Object -ExpandProperty FeatureName

        foreach ($feature in $FeaturesConfig.Feature) {
            # Validate feature exists
            if ($feature.Name -notin $availableFeatures) {
                Write-Log "Feature not found: $($feature.Name)" -Level Error
                Write-ErrorMessage -msg "Feature not found: $($feature.Name)"
                continue
            }

            Write-SystemMessage -msg1 "- Processing feature: " -msg2 $feature.Name
            Write-Log "Processing feature: $($feature.Name) with state: $($feature.State)"
            
            try {
                switch ($feature.State.ToLower()) {
                    'enabled' {
                        Write-Log "Enabling feature: $($feature.Name)"
                        $currentState = Get-WindowsOptionalFeature -Online -FeatureName $feature.Name
                        if ($currentState.State -eq 'Enabled') {
                            Write-Log "Feature $($feature.Name) is already enabled" -Level Warning
                            Write-SystemMessage -msg1 "! Feature already enabled: " -msg2 $feature.Name -msg1Color "DarkYellow"
                            continue
                        }
                        $result = Enable-WindowsOptionalFeature -Online -FeatureName $feature.Name -NoRestart | Out-Null
                        if ($result.RestartNeeded) {
                            $script:restartRequired = $true
                            Write-Log "Restart will be required for feature: $($feature.Name)"
                        }
                        Write-SuccessMessage -msg "Feature enabled: $($feature.Name)"
                    }
                    'disabled' {
                        Write-Log "Disabling feature: $($feature.Name)"
                        $currentState = Get-WindowsOptionalFeature -Online -FeatureName $feature.Name
                        if ($currentState.State -eq 'Disabled') {
                            Write-Log "Feature $($feature.Name) is already disabled" -Level Warning
                            Write-SystemMessage -msg1 "! Feature already disabled: " -msg2 $feature.Name -msg1Color "DarkYellow"
                            continue
                        }
                        $result = Disable-WindowsOptionalFeature -Online -FeatureName $feature.Name -NoRestart | Out-Null
                        if ($result.RestartNeeded) {
                            $script:restartRequired = $true
                            Write-Log "Restart will be required for feature: $($feature.Name)"
                        }
                        Write-SuccessMessage -msg "Feature disabled: $($feature.Name)"
                    }
                    default {
                        Write-Log "Invalid state specified for feature $($feature.Name): $($feature.State)" -Level Warning
                        Write-ErrorMessage -msg "Invalid state specified for feature: $($feature.Name)"
                    }
                }
            } catch {
                $errorMsg = "Failed to configure feature $($feature.Name): $($_.Exception.Message)"
                Write-Log $errorMsg -Level Error
                Write-ErrorMessage -msg $errorMsg
                if ($_.Exception.Message -match "restart") {
                    $script:restartRequired = $true
                }
            }
        }

        Write-Log "Windows features configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring Windows features: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure Windows features"
        return $false
    }
}

# Function to configure Google products
function Set-GoogleConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$GoogleConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Google Products"

        # Google Drive
        if ($GoogleConfig.InstallGoogleDrive -eq 'true') {
            if (Test-ProgramInstalled 'Google Drive') {
                Write-Log "Google Drive already installed. Skipping..."
                Write-SystemMessage -msg1 "- Google Drive is already installed. Skipping installation."
                return $true
            }

            Write-Log "Installing Google Drive..."
            Write-SystemMessage -msg1 "- Installing: " -msg2 "Google Drive"

            $driveSetupUrl = "https://dl.google.com/drive-file-stream/GoogleDriveSetup.exe"
            $driveSetupPath = Join-Path $env:TEMP "GoogleDriveSetup.exe"
            $script:tempFiles += $driveSetupPath
            
            Invoke-WebRequest -Uri $driveSetupUrl -OutFile $driveSetupPath | Out-Null
            Start-Process -FilePath $driveSetupPath -ArgumentList "/silent /install" -Wait | Out-Null
            Write-SuccessMessage -msg "Google Drive installed successfully"
        } elseif ($GoogleConfig.InstallGoogleDrive -eq 'false') {
            Write-Log "Uninstalling Google Drive..."
            Write-SystemMessage -msg1 "- Uninstalling: " -msg2 "Google Drive"
            try {
                $uninstallString = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
                    Where-Object { $_.DisplayName -like "*Google Drive*" }).UninstallString
                if ($uninstallString) {
                    Start-Process -FilePath $uninstallString -ArgumentList "/silent /uninstall" -Wait | Out-Null
                    Write-SuccessMessage -msg "Google Drive uninstalled successfully"
                }
            } catch {
                Write-Log "Failed to uninstall Google Drive: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to uninstall Google Drive"
            }
        }

        # Google Chrome
        if ($GoogleConfig.InstallGoogleChrome -eq 'true') {
            Write-Log "Installing Google Chrome..."
            Write-SystemMessage -msg1 "- Installing: " -msg2 "Google Chrome"
            
            $chromeSetupUrl = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
            $chromeSetupPath = Join-Path $env:TEMP "chrome_installer.exe"
            $script:tempFiles += $chromeSetupPath
            
            Invoke-WebRequest -Uri $chromeSetupUrl -OutFile $chromeSetupPath | Out-Null
            Start-Process -FilePath $chromeSetupPath -ArgumentList "/silent /install" -Wait | Out-Null
            Write-SuccessMessage -msg "Google Chrome installed successfully"
        } elseif ($GoogleConfig.InstallGoogleChrome -eq 'false') {
            Write-Log "Uninstalling Google Chrome..."
            Write-SystemMessage -msg1 "- Uninstalling: " -msg2 "Google Chrome"
            try {
                $uninstallString = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
                    Where-Object { $_.DisplayName -like "*Google Chrome*" }).UninstallString
                if ($uninstallString) {
                    Start-Process -FilePath $uninstallString -ArgumentList "--uninstall --force-uninstall" -Wait | Out-Null
                    Write-SuccessMessage -msg "Google Chrome uninstalled successfully"
                }
            } catch {
                Write-Log "Failed to uninstall Google Chrome: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to uninstall Google Chrome"
            }
        }

        # Google Credential Provider for Windows (GCPW)
        if ($GoogleConfig.InstallGCPW -eq 'true') {
            if (-not $GoogleConfig.EnrollmentToken) {
                Write-Log "GCPW installation skipped - EnrollmentToken is required but was not provided" -Level Error
                Write-ErrorMessage -msg "GCPW installation requires an EnrollmentToken in the configuration"
                return $false
            }

            $gcpwFileName = if ([Environment]::Is64BitOperatingSystem) {
                'gcpwstandaloneenterprise64.msi'
            } else {
                'gcpwstandaloneenterprise.msi'
            }
    
            $gcpwUrl = "https://dl.google.com/credentialprovider/$gcpwFileName"

            if (Test-ProgramInstalled 'Credential Provider') {
                Write-Log "GCPW already installed. Skipping..."
            } else {
                Write-Log "Installing Google Credential Provider for Windows (GCPW)..."
                Write-SystemMessage -msg1 "- Installing: " -msg2 "Google Credential Provider for Windows (GCPW)"
                
                Invoke-WebRequest -Uri $gcpwUrl -OutFile "$env:TEMP\$gcpwFileName" | Out-Null
    
                try {
                    $arguments = "/i ""$env:TEMP\$gcpwFileName"" /quiet"
                    $installProcess = Start-Process msiexec.exe -ArgumentList $arguments -PassThru -Wait | Out-Null
    
                    if ($installProcess.ExitCode -eq 0) {
                        Write-Log "GCPW Installation completed successfully!"
                        
                        # Set the required EnrollmentToken
                        Set-RegistryModification -action add -path "HKLM:\SOFTWARE\Policies\Google\CloudManagement" -name "EnrollmentToken" -type "String" -value $GoogleConfig.EnrollmentToken | Out-Null
                        
                        # Only set domains_allowed_to_login if it was provided
                        if ($GoogleConfig.DomainsAllowedToLogin) {
                            Set-RegistryModification -action add -path "HKLM:\Software\Google\GCPW" -name "domains_allowed_to_login" -type "String" -value $GoogleConfig.DomainsAllowedToLogin | Out-Null
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

        } elseif ($GoogleConfig.InstallGCPW -eq 'false') {
            Write-Log "Uninstalling Google Credential Provider for Windows (GCPW)..."
            Write-SystemMessage -msg1 "- Uninstalling: " -msg2 "Google Credential Provider for Windows (GCPW)"
            try {
                $uninstallString = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
                    Where-Object { $_.DisplayName -like "*Google Credential Provider*" }).UninstallString
                if ($uninstallString) {
                    Start-Process msiexec.exe -ArgumentList "/x $uninstallString /quiet" -Wait | Out-Null
                    Write-SuccessMessage -msg "GCPW uninstalled successfully"
                }
            } catch {
                Write-Log "Failed to uninstall GCPW: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to uninstall GCPW"
            }
        }

        # Allowed Domains
        if ($GoogleConfig.DomainsAllowedToLogin) {
            Write-Log "Setting allowed domains..."
            Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AuthServerAllowlist" -Type String -Value $GoogleConfig.DomainsAllowedToLogin
        }

        Write-Log "Google configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring Google products: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Function to configure Microsoft Office
function Set-OfficeConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$OfficeConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Microsoft Office"

        # Create Office configuration XML
        $configXml = @"
<Configuration>
    <Add OfficeClientEdition="$($OfficeConfig.OfficeClientEdition)" Channel="$($OfficeConfig.Channel)">
        <Product ID="$($OfficeConfig.ProductID)">
            <Language ID="$($OfficeConfig.LanguageID)" />
        </Product>
    </Add>
    <Display Level="$($OfficeConfig.DisplayLevel)" AcceptEULA="TRUE" />
    <Property Name="FORCEAPPSHUTDOWN" Value="TRUE" />
    <Updates Enabled="$($OfficeConfig.UpdatesEnabled.ToString().ToLower())" />
    <RemoveMSI />
</Configuration>
"@
        $configPath = Join-Path $env:TEMP "OfficeConfig.xml"
        $configXml | Out-File -FilePath $configPath -Encoding UTF8
        $script:tempFiles += $configPath

        # Download Office Deployment Tool
        Write-SystemMessage -msg1 "- Downloading Office Deployment Tool..."
        Write-Log "Downloading Office Deployment Tool..."
        
        $odtUrl = "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_16731-20398.exe"
        $odtPath = Join-Path $env:TEMP "ODT.exe"
        $script:tempFiles += $odtPath
        
        try {
            Invoke-WebRequest -Uri $odtUrl -OutFile $odtPath | Out-Null
            Write-SuccessMessage -msg "Office Deployment Tool downloaded successfully"
        } catch {
            Write-Log "Failed to download Office Deployment Tool: $($_.Exception.Message)" -Level Error
            Write-ErrorMessage -msg "Failed to download Office Deployment Tool"
            return $false
        }

        # Extract ODT
        Write-SystemMessage -msg1 "- Extracting Office Deployment Tool..."
        Write-Log "Extracting Office Deployment Tool..."
        Start-Process -FilePath $odtPath -ArgumentList "/quiet /extract:$env:TEMP\ODT" -Wait | Out-Null

        # Install Office
        Write-SystemMessage -msg1 "- Installing Microsoft Office..."
        Write-Log "Installing Microsoft Office..."
        $setupPath = Join-Path $env:TEMP "ODT\setup.exe"
        Start-Process -FilePath $setupPath -ArgumentList "/configure `"$configPath`"" -Wait | Out-Null

        # Activate Office if license key provided
        if ($OfficeConfig.LicenseKey) {
            Write-SystemMessage -msg1 "- Activating Microsoft Office..."
            Write-Log "Activating Microsoft Office..."
            
            $osppPath = "${env:ProgramFiles(x86)}\Microsoft Office\Office16\OSPP.VBS"
            if (Test-Path $osppPath) {
                try {
                    cscript $osppPath /inpkey:$($OfficeConfig.LicenseKey) | Out-Null
                    Start-Sleep -Seconds 2
                    cscript $osppPath /act | Out-Null
                    Write-SuccessMessage -msg "Microsoft Office activated successfully"
                } catch {
                    Write-Log "Failed to activate Office: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to activate Office"
                }
            } else {
                Write-Log "Office activation path not found: $osppPath" -Level Warning
                Write-ErrorMessage -msg "Office activation path not found"
            }
        }

        Write-Log "Office configuration completed successfully"
        Write-SuccessMessage -msg "Microsoft Office installation completed"
        return $true
    }
    catch {
        Write-Log "Error configuring Office: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure Microsoft Office"
        return $false
    }
}

# Function to configure theme settings
function Set-ThemeConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$ThemeConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Theme Settings"

        # Theme Mode (Dark/Light)
        if ($ThemeConfig.DarkMode) {
            if ($ThemeConfig.DarkMode -eq 'true') {
                Write-SystemMessage -msg1 "- Enabling dark mode..."
                try {
                    Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
                    Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
                    Write-SuccessMessage -msg "Dark mode enabled"
                }
                catch {
                    Write-Log "Failed to enable dark mode: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to enable dark mode"
                }
            }
            elseif ($ThemeConfig.DarkMode -eq 'false') {
                Write-SystemMessage -msg1 "- Enabling light mode..."
                try {
                    Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 1
                    Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 1
                    Write-SuccessMessage -msg "Light mode enabled"
                }
                catch {
                    Write-Log "Failed to enable light mode: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to enable light mode"
                }
            }
        }

        # Transparency Effects
        if ($ThemeConfig.TransparencyEffects) {
            if ($ThemeConfig.TransparencyEffects -eq 'false') {
                Write-SystemMessage -msg1 "- Disabling transparency effects..."
                try {
                    Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0
                    Write-SuccessMessage -msg "Transparency effects disabled"
                }
                catch {
                    Write-Log "Failed to disable transparency effects: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to disable transparency effects"
                }
            }
            elseif ($ThemeConfig.TransparencyEffects -eq 'true') {
                Write-SystemMessage -msg1 "- Enabling transparency effects..."
                try {
                    Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 1
                    Write-SuccessMessage -msg "Transparency effects enabled"
                }
                catch {
                    Write-Log "Failed to enable transparency effects: $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to enable transparency effects"
                }
            }
        }

        # Wallpaper
        if ($ThemeConfig.WallpaperPath) {
            Write-SystemMessage -msg1 "- Setting wallpaper from: " -msg2 $ThemeConfig.WallpaperPath
            try {
                $wallpaperPath = $ThemeConfig.WallpaperPath
                if ($wallpaperPath -match "^https?://") {
                    try {
                        Write-Log "Downloading wallpaper from: $wallpaperPath"
                    
                        # Extract filename from URL or use a default
                        $wallpaperFileName = [System.IO.Path]::GetFileName($wallpaperPath)
                        if ([string]::IsNullOrEmpty($wallpaperFileName)) {
                            $wallpaperFileName = "wallpaper$(([System.IO.Path]::GetExtension($wallpaperPath)))"
                        }
                        
                        Invoke-WebRequest -Uri $wallpaperPath -OutFile "$env:TEMP\$wallpaperFileName" | Out-Null

                        $wallpaperPath = "$env:TEMP\$wallpaperFileName"
                        $script:tempFiles += $wallpaperPath
                        Write-Log "Wallpaper downloaded successfully to: $wallpaperPath"
                    }
                    catch {
                        Write-Log "Failed to download wallpaper from: $wallpaperPath" -Level Error
                        Write-ErrorMessage -msg "Failed to download wallpaper"
                        return $false
                    }
                }

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
                Write-SuccessMessage -msg "Wallpaper set successfully"
            }
            catch {
                Write-Log "Error setting wallpaper: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set wallpaper"
            }
        }

        # Lock Screen
        if ($ThemeConfig.LockScreenPath) {
            Write-SystemMessage -msg1 "- Setting lock screen from: " -msg2 $ThemeConfig.LockScreenPath
            try {
                $lockScreenPath = $ThemeConfig.LockScreenPath
                if ($lockScreenPath -match "^https?://") {
                    try {
                        Write-Log "Downloading lock screen from: $lockScreenPath"
                    
                        # Extract filename from URL or use a default
                        $lockScreenFileName = [System.IO.Path]::GetFileName($lockScreenPath)
                        if ([string]::IsNullOrEmpty($lockScreenFileName)) {
                            $lockScreenFileName = "lockscreen$(([System.IO.Path]::GetExtension($lockScreenPath)))"
                        }
                        
                        Invoke-WebRequest -Uri $lockScreenPath -OutFile "$env:TEMP\$lockScreenFileName" | Out-Null

                        $lockScreenPath = "$env:TEMP\$lockScreenFileName"
                        $script:tempFiles += $lockScreenPath
                        Write-Log "Lock screen downloaded successfully to: $lockScreenPath"
                    }
                    catch {
                        Write-Log "Failed to download lock screen from: $lockScreenPath" -Level Error
                        Write-ErrorMessage -msg "Failed to download lock screen"
                        return $false
                    }
                }

                # Load necessary Windows Runtime namespaces for Lock Screen
                [Windows.System.UserProfile.LockScreen, Windows.System.UserProfile, ContentType = WindowsRuntime] | Out-Null
                Add-Type -AssemblyName System.Runtime.WindowsRuntime

                # Helper function to handle asynchronous tasks
                $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]

                Function Await($WinRtTask, $ResultType) {
                    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
                    $netTask = $asTask.Invoke($null, @($WinRtTask))
                    $netTask.Wait(-1) | Out-Null
                    $netTask.Result
                }

                Function AwaitAction($WinRtAction) {
                    $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and !$_.IsGenericMethod })[0]
                    $netTask = $asTask.Invoke($null, @($WinRtAction))
                    $netTask.Wait(-1) | Out-Null
                }

                # Load Windows.Storage namespace to work with files
                [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime] | Out-Null

                # Check if the image path exists
                if (-not (Test-Path -Path $lockScreenPath)) {
                    Write-Log "The lock screen image file at '$lockScreenPath' does not exist. Please provide a valid file path." -Level Error
                    return @{
                }

                # Retrieve the image file asynchronously
                $image = Await([Windows.Storage.StorageFile]::GetFileFromPathAsync($lockScreenPath)) ([Windows.Storage.StorageFile])

                # Set the lock screen image asynchronously
                AwaitAction([Windows.System.UserProfile.LockScreen]::SetImageFileAsync($image))
        
                Write-Log "Lock screen set successfully."
                Write-SuccessMessage -msg "Lock screen set successfully"
            }
        }
            catch {
                Write-Log "Error setting lock screen: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set lock screen"
            }
        }

        # Desktop Icon Size
        if ($ThemeConfig.DesktopIconSize) {
            Write-SystemMessage -msg1 "- Setting desktop icon size..."
            Write-Log "Setting desktop icon size..."
            try {
                $sizeValue = switch ($ThemeConfig.DesktopIconSize) {
                    "Small" { 0 }
                    "Medium" { 1 }
                    "Large" { 2 }
                    default {
                        Write-Log "Invalid desktop icon size specified: $($ThemeConfig.DesktopIconSize). Using Medium." -Level Warning
                        1
                    }
                }
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" -Name "IconSize" -Type DWord -Value $sizeValue
                Write-SuccessMessage -msg "Desktop icon size set successfully"
            }
            catch {
                Write-Log "Failed to set desktop icon size: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to set desktop icon size"
            }
        }

        Write-Log "Theme configuration completed successfully"
        return $true
    
}
    catch {
        Write-Log "Error configuring theme settings: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure theme settings"
        return $false
    }
}

# Function to apply system tweaks
function Set-TweaksConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$TweaksConfig
    )
    
    try {
        Write-SystemMessage -Title "Applying System Tweaks"

        # Classic Right-Click Menu
        if ($TweaksConfig.ClassicRightClickMenu -eq 'true') {
            Write-Log "Enabling classic right-click menu..."
            Write-SystemMessage -msg1 "- Enabling classic right-click menu..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Type String -Value ""
                Write-SuccessMessage -msg "Classic right-click menu enabled"
            } catch {
                Write-Log "Failed to enable classic right-click menu: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable classic right-click menu"
            }
        } elseif ($TweaksConfig.ClassicRightClickMenu -eq 'false') {
            Write-Log "Disabling classic right-click menu..."
            Write-SystemMessage -msg1 "- Disabling classic right-click menu..."
            try {
                Remove-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
                Write-SuccessMessage -msg "Classic right-click menu disabled"
            } catch {
                Write-Log "Failed to disable classic right-click menu: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable classic right-click menu"
            }
        }

        # God Mode
        if ($TweaksConfig.EnableGodMode -eq 'true') {
            Write-Log "Creating God Mode folder..."
            Write-SystemMessage -msg1 "- Creating God Mode folder..."
            try {
                $godModePath = Join-Path $env:USERPROFILE "Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
                if (-not (Test-Path $godModePath)) {
                    New-Item -Path $godModePath -ItemType Directory -Force | Out-Null
                    Write-SuccessMessage -msg "God Mode folder created"
                }
            } catch {
                Write-Log "Failed to create God Mode folder: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to create God Mode folder"
            }
        } elseif ($TweaksConfig.EnableGodMode -eq 'false') {
            Write-Log "Removing God Mode folder..."
            Write-SystemMessage -msg1 "- Removing God Mode folder..."
            try {
                $godModePath = Join-Path $env:USERPROFILE "Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
                if (Test-Path $godModePath) {
                    Remove-Item -Path $godModePath -Force -Recurse | Out-Null
                    Write-SuccessMessage -msg "God Mode folder removed"
                }
            } catch {
                Write-Log "Failed to remove God Mode folder: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to remove God Mode folder"
            }
        }

        Write-Log "System tweaks applied successfully"
        return $true
    }
    catch {
        Write-Log "Error applying system tweaks: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Function to configure network settings
function Set-NetworkConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$NetworkConfig
    )
    
    try {
        Write-SystemMessage -Title "Configuring Network Settings"

        # Network Discovery
        if ($NetworkConfig.NetworkDiscovery -eq 'true') {
            Write-SystemMessage -msg1 "- Enabling Network Discovery..."
            Write-Log "Enabling Network Discovery..."
            try {
                Get-NetFirewallRule -Group "@FirewallAPI.dll,-32752" | Set-NetFirewallRule -Profile Private -Enabled True
                Set-NetFirewallRule -Name "FPS-SMB-In-TCP" -Enabled True
                Write-SuccessMessage -msg "Network Discovery enabled"
            } catch {
                Write-Log "Failed to enable Network Discovery: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable Network Discovery"
            }
        } elseif ($NetworkConfig.NetworkDiscovery -eq 'false') {
            Write-SystemMessage -msg1 "- Disabling Network Discovery..."
            Write-Log "Disabling Network Discovery..."
            try {
                Get-NetFirewallRule -Group "@FirewallAPI.dll,-32752" | Set-NetFirewallRule -Profile Private -Enabled False
                Set-NetFirewallRule -Name "FPS-SMB-In-TCP" -Enabled False
                Write-SuccessMessage -msg "Network Discovery disabled"
            } catch {
                Write-Log "Failed to disable Network Discovery: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable Network Discovery"
            }
        }

        # File and Printer Sharing
        if ($NetworkConfig.FileAndPrinterSharing -eq 'true') {
            Write-SystemMessage -msg1 "- Enabling File and Printer Sharing..."
            Write-Log "Enabling File and Printer Sharing..."
            try {
                Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True
                Write-SuccessMessage -msg "File and Printer Sharing enabled"
            } catch {
                Write-Log "Failed to enable File and Printer Sharing: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to enable File and Printer Sharing"
            }
        } elseif ($NetworkConfig.FileAndPrinterSharing -eq 'false') {
            Write-SystemMessage -msg1 "- Disabling File and Printer Sharing..."
            Write-Log "Disabling File and Printer Sharing..."
            try {
                Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled False
                Write-SuccessMessage -msg "File and Printer Sharing disabled"
            } catch {
                Write-Log "Failed to disable File and Printer Sharing: $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to disable File and Printer Sharing"
            }
        }

        # Network Drives
        if ($NetworkConfig.NetworkDrives) {
            foreach ($drive in $NetworkConfig.NetworkDrives.Drive) {
                # Validate drive letter format
                if (-not ($drive.Letter -match "^[A-Z]$")) {
                    Write-Log "Invalid drive letter format: $($drive.Letter). Must be a single letter A-Z." -Level Error
                    Write-ErrorMessage -msg "Invalid drive letter format: $($drive.Letter)"
                    continue
                }

                # Validate network path format
                if (-not ($drive.Path -match "^\\\\[^\/\\:*?""<>|]+\\.*")) {
                    Write-Log "Invalid network path format: $($drive.Path). Must be UNC path (\\server\share)." -Level Error
                    Write-ErrorMessage -msg "Invalid network path format: $($drive.Path)"
                    continue
                }

                Write-SystemMessage -msg1 "- Mapping network drive $($drive.Letter) to: " -msg2 $drive.Path
                Write-Log "Mapping network drive $($drive.Letter) to $($drive.Path)"
                
                try {
                    # Remove existing drive mapping if it exists
                    if (Test-Path "$($drive.Letter):") {
                        Write-Log "Removing existing drive mapping for $($drive.Letter):"
                        Remove-PSDrive -Name $drive.Letter -Force -ErrorAction SilentlyContinue
                        net use "$($drive.Letter):" /delete /y
                    }

                    # Handle credentials if provided
                    $mappingParams = @{
                        Name = $drive.Letter
                        PSProvider = 'FileSystem'
                        Root = $drive.Path
                        Persist = $true
                        ErrorAction = 'Stop'
                    }

                    if ($drive.Username -and $drive.Password) {
                        $securePassword = ConvertTo-SecureString $drive.Password -AsPlainText -Force
                        $credential = New-Object System.Management.Automation.PSCredential ($drive.Username, $securePassword)
                        $mappingParams['Credential'] = $credential
                    }

                    # Test network path accessibility
                    if (Test-Path -Path $drive.Path -ErrorAction Stop) {
                        New-PSDrive @mappingParams
                        Write-SuccessMessage -msg "Network drive $($drive.Letter): mapped successfully"
                    } else {
                        Write-Log "Network path not accessible or does not exist: $($drive.Path)" -Level Error
                        Write-ErrorMessage -msg "Network path not accessible: $($drive.Path)"
                    }
                } catch {
                    Write-Log "Failed to map drive $($drive.Letter): $($_.Exception.Message)" -Level Error
                    Write-ErrorMessage -msg "Failed to map network drive $($drive.Letter):"
                }
            }
        }

        Write-Log "Network configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring network settings: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to configure network settings"
        return $false
    }
}

# Function to perform file operations (copy, delete, etc.)
function Set-FileOperations {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$FileConfig
    )
    
    try {
        Write-SystemMessage -Title "Performing File Operations"

        # Copy Operations
        if ($FileConfig.Copy) {
            foreach ($file in $FileConfig.Copy.File) {
                # Validate source and destination paths
                if (-not $file.Source -or -not $file.Destination) {
                    Write-Log "Invalid file operation: Source or Destination missing" -Level Error
                    Write-ErrorMessage -msg "Invalid file operation: Source or Destination missing"
                    continue
                }

                # Validate file paths for invalid characters
                $invalidChars = [IO.Path]::GetInvalidPathChars()
                if (($file.Source.IndexOfAny($invalidChars) -ge 0) -or ($file.Destination.IndexOfAny($invalidChars) -ge 0)) {
                    Write-Log "Invalid characters in path: Source=$($file.Source), Destination=$($file.Destination)" -Level Error
                    Write-ErrorMessage -msg "Invalid characters in file path"
                    continue
                }

                Write-SystemMessage -msg1 "- Copying file from: " -msg2 $file.Source
                Write-Log "Copying file from $($file.Source) to $($file.Destination)"
                
                try {
                    # Create destination directory if it doesn't exist
                    $destinationDir = Split-Path -Parent $file.Destination
                    if (-not (Test-Path $destinationDir)) {
                        New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
                        Write-Log "Created destination directory: $destinationDir"
                    }

                    # Copy file
                    if (Test-Path $file.Source) {
                        # Check if destination file exists
                        if (Test-Path $file.Destination) {
                            Write-Log "Destination file already exists, overwriting: $($file.Destination)" -Level Warning
                        }
                        Copy-Item -Path $file.Source -Destination $file.Destination -Force
                        Write-SuccessMessage -msg "File copied successfully"
                    } else {
                        Write-Log "Source file not found: $($file.Source)" -Level Warning
                        Write-ErrorMessage -msg "Source file not found: $($file.Source)"
                    }
                } catch {
                    Write-Log "Failed to copy file: $($_.Exception.Message)" -Level Warning
                    Write-ErrorMessage -msg "Failed to copy file"
                }
            }
        }

        # Delete Operations
        if ($FileConfig.Delete) {
            foreach ($file in $FileConfig.Delete.File) {
                # Validate file path
                if (-not $file) {
                    Write-Log "Invalid file operation: File path is empty" -Level Error
                    Write-ErrorMessage -msg "Invalid file operation: File path is empty"
                    continue
                }

                # Validate file path for invalid characters
                $invalidChars = [IO.Path]::GetInvalidPathChars()
                if ($file.IndexOfAny($invalidChars) -ge 0) {
                    Write-Log "Invalid characters in path: $file" -Level Error
                    Write-ErrorMessage -msg "Invalid characters in file path"
                    continue
                }

                Write-SystemMessage -msg1 "- Deleting file: " -msg2 $file
                Write-Log "Deleting file: $file"
                
                try {
                    if (Test-Path $file) {
                        # Check if file is read-only or system file
                        $fileInfo = Get-Item $file
                        if ($fileInfo.Attributes -match "ReadOnly|System") {
                            Write-Log "Warning: Attempting to delete protected file: $file" -Level Warning
                        }

                        Remove-Item -Path $file -Force
                        Write-SuccessMessage -msg "File deleted successfully"
                    } else {
                        Write-Log "File not found for deletion: $file" -Level Warning
                        Write-ErrorMessage -msg "File not found: $file"
                    }
                } catch {
                    $errorMsg = "Failed to delete file: $($_.Exception.Message)"
                    if ($_.Exception.Message -match "Access.*denied") {
                        $errorMsg += " (Access Denied)"
                    }
                    Write-Log $errorMsg -Level Warning
                    Write-ErrorMessage -msg "Failed to delete file"
                }
            }
        }

        Write-Log "File operations completed successfully"
        return $true
    }
    catch {
        Write-Log "Error performing file operations: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to perform file operations"
        return $false
    }
}

# Function to create shortcuts
function Set-Shortcuts {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$ShortcutConfig
    )
    
    try {
        Write-SystemMessage -Title "Creating Shortcuts"

        foreach ($shortcut in $ShortcutConfig.Shortcut) {
            # Validate required properties
            if (-not $shortcut.Name -or -not $shortcut.Target) {
                Write-Log "Invalid shortcut configuration: Name or Target missing" -Level Error
                Write-ErrorMessage -msg "Invalid shortcut configuration: Name or Target missing"
                continue
            }

            # Validate target path exists
            if (-not (Test-Path $shortcut.Target)) {
                Write-Log "Target path does not exist: $($shortcut.Target)" -Level Error
                Write-ErrorMessage -msg "Target path does not exist: $($shortcut.Target)"
                continue
            }

            Write-SystemMessage -msg1 "- Creating shortcut: " -msg2 $shortcut.Name
            Write-Log "Creating shortcut: $($shortcut.Name) -> $($shortcut.Target)"

            try {
                # Determine shortcut location
                $shortcutLocation = switch ($shortcut.Location) {
                    "Desktop" { [Environment]::GetFolderPath("Desktop") }
                    "StartMenu" { [Environment]::GetFolderPath("StartMenu") }
                    "Programs" { [Environment]::GetFolderPath("Programs") }
                    default { 
                        Write-Log "Invalid shortcut location specified: $($shortcut.Location). Using Desktop." -Level Warning
                        [Environment]::GetFolderPath("Desktop") 
                    }
                }

                # Validate shortcut location exists
                if (-not (Test-Path $shortcutLocation)) {
                    Write-Log "Shortcut location does not exist: $shortcutLocation" -Level Error
                    Write-ErrorMessage -msg "Shortcut location does not exist"
                    continue
                }

                $shortcutPath = Join-Path $shortcutLocation "$($shortcut.Name).lnk"

                # Check if shortcut already exists
                if (Test-Path $shortcutPath) {
                    Write-Log "Shortcut already exists, will be overwritten: $shortcutPath" -Level Warning
                }

                # Create WScript Shell object
                $WScriptShell = New-Object -ComObject WScript.Shell
                $Shortcut = $WScriptShell.CreateShortcut($shortcutPath)

                # Set shortcut properties
                $Shortcut.TargetPath = $shortcut.Target
                
                if ($shortcut.Arguments) {
                    Write-Log "Setting shortcut arguments: $($shortcut.Arguments)"
                    $Shortcut.Arguments = $shortcut.Arguments
                }
                
                if ($shortcut.WorkingDirectory) {
                    # Validate working directory exists
                    if (-not (Test-Path $shortcut.WorkingDirectory)) {
                        Write-Log "Working directory does not exist: $($shortcut.WorkingDirectory)" -Level Warning
                    }
                    Write-Log "Setting working directory: $($shortcut.WorkingDirectory)"
                    $Shortcut.WorkingDirectory = $shortcut.WorkingDirectory
                }
                
                if ($shortcut.IconLocation) {
                    # Validate icon file exists
                    $iconPath = ($shortcut.IconLocation -split ',')[0]
                    if (-not (Test-Path $iconPath)) {
                        Write-Log "Icon file does not exist: $iconPath" -Level Warning
                    }
                    Write-Log "Setting icon location: $($shortcut.IconLocation)"
                    $Shortcut.IconLocation = $shortcut.IconLocation
                }

                # Save shortcut
                $Shortcut.Save()
                Write-SuccessMessage -msg "Shortcut created successfully: $($shortcut.Name)"

            } catch {
                Write-Log "Failed to create shortcut $($shortcut.Name): $($_.Exception.Message)" -Level Error
                Write-ErrorMessage -msg "Failed to create shortcut: $($shortcut.Name)"
            } finally {
                if ($WScriptShell) {
                    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($WScriptShell) | Out-Null
                }
            }
        }

        Write-Log "Shortcuts creation completed successfully"
        return $true
    }
    catch {
        Write-Log "Error creating shortcuts: $($_.Exception.Message)" -Level Error
        Write-ErrorMessage -msg "Failed to create shortcuts"
        return $false
    }
}


# Main Execution Block
try {

    Clear-Host
    Write-SystemMessage -Title "Starting Winforge Configuration"

    # Verify running as administrator
    if (-not (Test-AdminPrivileges)) {
        throw "This script requires administrative privileges"
    }

    # Initialize configuration status hashtable with counts
    $configStatus = @{}

    # Load and validate configuration
    $configXML = Get-WinforgeConfig -Path $ConfigPath

    # Set System Checkpoint
    Set-SystemCheckpoint

    # System Configuration
    if ($configXML.System) {
        $configStatus['System'] = Set-SystemConfiguration -SystemConfig $configXML.System
    }

    # Environment Variables
    if ($configXML.EnvironmentVariables) {
        $configStatus['Environment'] = Set-EnvironmentVariables -EnvConfig $configXML.EnvironmentVariables
    }

    # Windows Activation
    if ($configXML.Activation) {
        $configStatus['Activation'] = Set-WindowsActivation -ActivationConfig $configXML.Activation
    }

    # Windows Update
    if ($configXML.WindowsUpdate) {
        $configStatus['WindowsUpdate'] = Set-WindowsUpdateConfiguration -UpdateConfig $configXML.WindowsUpdate
    }

    # Taskbar
    if ($configXML.Taskbar) {
        $configStatus['Taskbar'] = Set-TaskbarConfiguration -TaskbarConfig $configXML.Taskbar
    }

    # Privacy
    if ($configXML.Privacy) {
        $configStatus['Privacy'] = Set-PrivacyConfiguration -PrivacyConfig $configXML.Privacy
    }

    # Security
    if ($configXML.Security) {
        $configStatus['Security'] = Set-SecurityConfiguration -SecurityConfig $configXML.Security
    }

    # Applications
    if ($configXML.Applications) {
        $configStatus['Applications'] = Install-Applications -AppConfig $configXML.Applications
    }

    # Fonts
    if ($configXML.Fonts) {
        $configStatus['Fonts'] = Install-Fonts -FontConfig $configXML.Fonts
    }

    # Power
    if ($configXML.Power) {
        $configStatus['Power'] = Set-PowerConfiguration -PowerConfig $configXML.Power
    }

    # Registry
    if ($configXML.Registry) {
        $configStatus['Registry'] = Set-RegistryEntries -RegistryConfig $configXML.Registry
    }

    # Scheduled Tasks
    if ($configXML.Tasks) {
        $configStatus['Tasks'] = Set-ScheduledTasksConfiguration -TasksConfig $configXML.Tasks
    }

    # Windows Features
    if ($configXML.WindowsFeatures) {
        $configStatus['WindowsFeatures'] = Set-WindowsFeaturesConfiguration -FeaturesConfig $configXML.WindowsFeatures
    }

    # Google Configuration
    if ($configXML.Google) {
        $configStatus['Google'] = Set-GoogleConfiguration -GoogleConfig $configXML.Google
    }

    # Office Configuration
    if ($configXML.Office) {
        $configStatus['Office'] = Set-OfficeConfiguration -OfficeConfig $configXML.Office
    }

    # Theme Configuration
    if ($configXML.Theme) {
        $configStatus['Theme'] = Set-ThemeConfiguration -ThemeConfig $configXML.Theme
    }

    # System Tweaks
    if ($configXML.Tweaks) {
        $configStatus['Tweaks'] = Set-TweaksConfiguration -TweaksConfig $configXML.Tweaks
    }

    # Network Configuration
    if ($configXML.Network) {
        $configStatus['Network'] = Set-NetworkConfiguration -NetworkConfig $configXML.Network
    }

    # File Operations
    if ($configXML.Files) {
        $configStatus['Files'] = Set-FileOperations -FileConfig $configXML.Files
    }

    # Shortcuts
    if ($configXML.Shortcuts) {
        $configStatus['Shortcuts'] = Set-Shortcuts -ShortcutConfig $configXML.Shortcuts
    }

    Write-SystemMessage -Title "Configuration Completed"
    $cleanup = Read-Host "Would you like to cleanup temporary files? (Y/N)"
    switch ($cleanup) {
        'Y' {
            Remove-TempFiles
        }
        'N' {
            Write-SystemMessage -msg1 "Temporary files will not be removed."
            Write-Log "Temporary files will not be removed."
        }
        default {
            Write-SystemMessage -msg1 "Invalid input." -msg2 "Select Y or N."
        }
    }

    # Display configuration status
    Write-SystemMessage -Title "Configuration Status"
    foreach ($item in $configStatus.GetEnumerator()) {
        $status = if ($item.Value) { "Success" } else { "Failed" }
        $color = if ($item.Value) { "Green" } else { "Red" }
        Write-Host "$($item.Key): " -NoNewline
        Write-Host $status -ForegroundColor $color
    }

    # Check if any configurations failed
    if ($configStatus.Values -contains $false) {
        Write-ErrorMessage -msg "Some configurations failed. Please check the logs for details."
        Pause
        return 1
    }
    else {
        Write-SuccessMessage -msg "All configurations completed successfully"
        if ($script:restartRequired) {
            Write-SystemMessage -Title "Restart Required" -msg1 "Some changes require a system restart to take effect."
            $restart = Read-Host "Would you like to restart now? (Y/N)"
            if ($restart -eq 'Y') {
                Restart-Computer -Force
                return 0
            }
        }
    }

    Write-SystemMessage -msg1 "Winforge will now exit."
    Pause
}
catch {
    Write-Log "$($_.Exception.Message)" -Level Error
    Write-ErrorMessage -msg "$($_.Exception.Message)"
    Pause
}
