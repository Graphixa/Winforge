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

$winforgeVersion = '0.2.1'


$ProgressPreference = 'SilentlyContinue'

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

function Write-SystemMessage {
    param (
        [Parameter()]
        [string]$title = '',
  
        [Parameter()]
        [string]$msg = '',

        [Parameter()]
        [string]$value = '',
  
        [Parameter()]
        [ConsoleColor]$titleColor = 'DarkMagenta',
  
        [Parameter()]
        [ConsoleColor]$msgColor = 'Cyan',

        [Parameter()]
        [ConsoleColor]$valueColor = 'White',

        [Parameter()]
        [switch]$errorMsg = $false,

        [Parameter()]
        [switch]$warningMsg = $false,

        [Parameter()]
        [switch]$successMsg = $false
    )

    # Initialize script variables if not exists
    if (-not (Test-Path variable:script:lastMessageCursorPosition)) {
        $script:lastMessageCursorPosition = $null
        $script:lastMessage = $null
        $script:lastValue = $null
    }
    
    # Handle title blocks
    if ($PSBoundParameters.ContainsKey('title')) {
        Write-Host "`n"
        $titleText = " $($title.ToUpper()) "
        Write-Host $titleText -ForegroundColor White -BackgroundColor $titleColor -NoNewline
        Write-Host "`n`n"
        $script:lastMessageCursorPosition = $null
        $script:lastMessage = $null
        $script:lastValue = $null
        return
    }

    # Define status message properties
    $statusTypes = @{
        successMsg = @{ symbol = "✓"; text = "SUCCESS"; color = "Green" }
        warningMsg = @{ symbol = "⚠ "; text = "WARNING"; color = "DarkYellow" }
        errorMsg = @{ symbol = "x"; text = "ERROR"; color = "Red" }
    }

    # Handle msg and value combinations
    if ($PSBoundParameters.ContainsKey('msg') -or $PSBoundParameters.ContainsKey('value')) {
        # If it's a status message with msg/value, handle differently
        $statusType = $statusTypes.Keys | Where-Object { $PSBoundParameters.ContainsKey($_) } | Select-Object -First 1
        if ($statusType) {
            $status = $statusTypes[$statusType]
            if ($script:lastMessageCursorPosition -and $script:lastMessage) {
                # Append to previous line
                $host.UI.RawUI.CursorPosition = $script:lastMessageCursorPosition
                Write-Host (" " * ($host.UI.RawUI.BufferSize.Width - 1))
                $host.UI.RawUI.CursorPosition = $script:lastMessageCursorPosition
                Write-Host " - $script:lastMessage" -ForegroundColor $msgColor -NoNewline
                if ($script:lastValue) {
                    Write-Host ": " -ForegroundColor $msgColor -NoNewline
                    Write-Host "$script:lastValue" -ForegroundColor $valueColor -NoNewline
                }
                Write-Host " - $($status.symbol) $($status.text)" -ForegroundColor $status.color -NoNewline
                if ($PSBoundParameters.ContainsKey('msg')) {
                    Write-Host ": " -ForegroundColor $status.color -NoNewline
                    Write-Host "$msg" -ForegroundColor DarkGray -NoNewline
                    if ($PSBoundParameters.ContainsKey('value')) {
                        Write-Host ": " -ForegroundColor $status.color -NoNewline
                        Write-Host "$value" -ForegroundColor Gray
                    } else {
                        Write-Host ""
                    }
                } else {
                    Write-Host ""
                }
            } else {
                # New status message line
                Write-Host " $($status.symbol) $($status.text)" -ForegroundColor $status.color -NoNewline
                if ($PSBoundParameters.ContainsKey('msg')) {
                    Write-Host " | " -ForegroundColor DarkGray -NoNewline
                    Write-Host "$msg" -ForegroundColor DarkGray -NoNewline
                    if ($PSBoundParameters.ContainsKey('value')) {
                        Write-Host ": " -ForegroundColor $status.color -NoNewline
                        Write-Host "$value" -ForegroundColor Gray
                    } else {
                        Write-Host ""
                    }
                } else {
                    Write-Host ""
                }
            }
            $script:lastMessageCursorPosition = $null
            return
        }

        # Store for potential status append later
        $script:lastMessage = $msg
        $script:lastValue = $value

        if ($PSBoundParameters.ContainsKey('msg')) {
            Write-Host " - $msg" -ForegroundColor $msgColor -NoNewline
            if ($PSBoundParameters.ContainsKey('value')) {
                Write-Host ": " -ForegroundColor $msgColor -NoNewline
                Write-Host $value -ForegroundColor $valueColor
            } else {
                Write-Host ""
            }
        } else {
            Write-Host $value -ForegroundColor $valueColor
        }

        $script:lastMessageCursorPosition = $host.UI.RawUI.CursorPosition
        $script:lastMessageCursorPosition.Y -= 1
        return
    }

    # Handle standalone status messages
    $statusType = $statusTypes.Keys | Where-Object { $PSBoundParameters.ContainsKey($_) } | Select-Object -First 1
    if ($statusType) {
        $status = $statusTypes[$statusType]
        if ($script:lastMessageCursorPosition -and $script:lastMessage) {
            $host.UI.RawUI.CursorPosition = $script:lastMessageCursorPosition
            Write-Host (" " * ($host.UI.RawUI.BufferSize.Width - 1))
            $host.UI.RawUI.CursorPosition = $script:lastMessageCursorPosition
            Write-Host " - $script:lastMessage" -ForegroundColor $msgColor -NoNewline
            if ($script:lastValue) {
                Write-Host ": " -ForegroundColor $msgColor -NoNewline
                Write-Host "$script:lastValue" -ForegroundColor $valueColor -NoNewline
            }
            Write-Host " - $($status.symbol) $($status.text)" -ForegroundColor $status.color -NoNewline
            if ($PSBoundParameters.ContainsKey('msg')) {
                Write-Host ": " -ForegroundColor $status.color -NoNewline
                Write-Host "$msg" -ForegroundColor $status.color -NoNewline
                if ($PSBoundParameters.ContainsKey('value')) {
                    Write-Host ": " -ForegroundColor $status.color -NoNewline
                    Write-Host "$value" -ForegroundColor $valueColor
                } else {
                    Write-Host ""
                }
            } else {
                Write-Host ""
            }
        } else {
            Write-Host " $($status.symbol) $($status.text)" -ForegroundColor $status.color -NoNewline
            if ($PSBoundParameters.ContainsKey('msg')) {
                Write-Host " | " -ForegroundColor DarkGray -NoNewline
                Write-Host "$msg" -ForegroundColor $status.color -NoNewline
                if ($PSBoundParameters.ContainsKey('value')) {
                    Write-Host ": " -ForegroundColor $status.color -NoNewline
                    Write-Host "$value" -ForegroundColor $valueColor
                } else {
                    Write-Host ""
                }
            } else {
                Write-Host ""
            }
        }

        if ($statusType -eq 'errorMsg' -and $_.Exception.Message) {
            Write-Host $_.Exception.Message -ForegroundColor Red
        }
        
        $script:lastMessageCursorPosition = $null
    }
}

Function Show-SplashScreen {
    param (
        [Parameter()]
        [string]$version = ''
    )
Write-Host @"
-----------------------------------------  
"@ -ForegroundColor Cyan
Write-Host @"
           _     ___                 
     _ _ _|_|___|  _|___ ___ ___ ___ 
    | | | | |   |  _| . |  _| . | -_|
    |_____|_|_|_|_| |___|_| |_  |___|
                            |___|                    
"@ -ForegroundColor DarkMagenta

Write-Host @"
-----------------------------------------
"@ -ForegroundColor Cyan
Write-Host @"
          FORGE YOUR OWN SYSTEM
"@ -ForegroundColor White
Write-Host @"
-----------------------------------------
"@ -ForegroundColor Cyan
Write-Host @"
                ver $version
           
"@ -ForegroundColor DarkGray
}


function Test-AdminPrivileges {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    
    if (-not $principal.IsInRole($adminRole)) {
        throw "This script requires administrative privileges"
    }
    
    # Additional check for UAC bypass attempts
    $elevationType = [Security.Principal.WindowsIdentity]::GetCurrent().Claims | 
        Where-Object { $_.Type -eq "WIN://ISAUTOELEVATEPRIVILEGE" }
    
    if ($elevationType) {
        throw "Please run PowerShell as Administrator explicitly."
    }
    
    return $true
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
        Write-SystemMessage -title "Winforge Configuration" 
        
        Write-SystemMessage -msg "Loading configuration file..."
      
        
        # Check if file exists
        if (-not (Test-Path $Path)) {
            Write-SystemMessage -errorMsg -msg "Configuration file not found"
            throw "Configuration file not found: $Path"
        }
        
        # Check if file is encrypted
        $isEncrypted = Test-EncryptedConfig -FilePath $Path
        if ($isEncrypted) {
            
            $maxAttempts = 5
            $attempt = 1
            $decrypted = $false

            while ($attempt -le $maxAttempts -and -not $decrypted) {
                
                Write-SystemMessage -msg "Configuration is encrypted. Please enter the password to decrypt it."
                Write-SystemMessage -msg "Attempts remaining" -value "$($maxAttempts - $attempt + 1)" -msgColor "Yellow"
                
                if ($attempt -gt 1) {
                    Write-SystemMessage -errorMsg -msg "Incorrect password." 
                    Write-SystemMessage -msg "Attempts remaining" -value "$($maxAttempts - $attempt + 1)" -msgColor "Yellow"
                }

                $password = Read-Host -AsSecureString "Password"
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
                $passwordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                
                # Check for empty password
                if ([string]::IsNullOrWhiteSpace($passwordText)) {
                    $attempt++
                    Write-SystemMessage -errorMsg -msg "Password cannot be empty." 
                    Write-SystemMessage -msg "Attempts remaining" -value "$($maxAttempts - $attempt + 1)" -msgColor "Yellow"
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                    Remove-Variable -Name passwordText -ErrorAction SilentlyContinue
                    continue
                }
                
                try {
                    $decryptResult = Convert-SecureConfig -FilePath $Path -IsEncrypting $false -Password $passwordText 2>$null
                    if ($decryptResult) {
                        Write-SystemMessage -successMsg "Configuration decrypted successfully." 
                        $decrypted = $true
                    }
                    else {
                        $attempt++
                        Write-SystemMessage -errorMsg -msg "Incorrect password." 
                        Write-SystemMessage -msg "Attempts remaining" -value "$($maxAttempts - $attempt + 1)" -msgColor "Yellow"
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
            # if (-not (Test-ConfigSchema -Xml $config)) {
            #     throw "Configuration failed schema validation"
            # }
        
        return $config.WinforgeConfig
        }
        catch [System.Xml.XmlException] {
            throw "Invalid XML in configuration file: $($_.Exception.Message)"
        }
    }
    catch {
        Write-Log "Failed to load configuration: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to load configuration" -value "$($_.Exception.Message)"
        
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

    Write-SystemMessage -title "Creating System Restore Point"
    Write-Log "Creating system restore point..." -Level Info

    try {
        # Check if System Restore is enabled
        $srEnabled = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if (-not $srEnabled) {
            Write-Log "System Restore is not enabled. Attempting to enable..." -Level Warning
            Enable-ComputerRestore -Drive "$env:systemdrive" -ErrorAction Stop | Out-Null
            Write-Log "System Restore enabled successfully" -Level Info
        }

        # Check available disk space (minimum 1GB recommended)
        $systemDrive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$env:systemdrive'"
        if ($systemDrive.FreeSpace -lt 1GB) {
            Write-Log "Insufficient disk space for system restore point" -Level Error
            Write-SystemMessage -errorMsg -msg "Insufficient disk space for system restore point"
            return $false
        }

        $date = Get-Date -Format "MM/dd/yyyy"
        $time = Get-Date -Format "HH:mm:ss"
        $snapshotName = "Winforge - $date"
        
        Write-Log "Creating system restore point. Snapshot Name: $snapshotName"
        Write-SystemMessage -msg "Creating System Restore Point | Snapshot Name" -value $snapshotName 
        
       
        Checkpoint-Computer -Description $snapshotName -RestorePointType "MODIFY_SETTINGS" -WarningAction SilentlyContinue
        Write-SystemMessage -successMsg
            
        return $true
    }
    catch {
        Write-Log "Error creating system restore point: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to create system restore point. Check Log for details."
        return $false
    }
}


# CONFIGURATION FUNCTIONS

function Set-SystemConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$SystemConfig
    )
    
    Write-SystemMessage -title "Configuring System Settings"

    try {
        
        $success = $true

        # Computer Name
        if ($SystemConfig.ComputerName) {
            try {
                Write-SystemMessage -msg "Setting computer name to" -value $SystemConfig.ComputerName
                $currentName = $env:COMPUTERNAME
                if ($currentName -ne $SystemConfig.ComputerName) {
                    Write-Log "Setting computer name to: $($SystemConfig.ComputerName)" -Level Info
                    Rename-Computer -NewName $SystemConfig.ComputerName -Force
                    $script:restartRequired = $true
                    Write-SystemMessage -successMsg
                } else {
                    Write-Log "Computer name is already set to: $($SystemConfig.ComputerName)" -Level Warning
                    Write-SystemMessage -warningMsg -msg "Computer name is already set to" -value "$($SystemConfig.ComputerName)"
                }
            }
            catch {
                Write-Log "Error setting computer name: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
                $success = $false
            }
        }

        # Locale and Timezone
        if ($SystemConfig.Locale) {
            Write-SystemMessage -msg "Setting system locale to" -value $SystemConfig.Locale
            Write-Log "Setting system locale to: $($SystemConfig.Locale)" -Level Info
            
            try {
                # Validate locale is supported
                if (Get-WinUserLanguageList | Where-Object { $_.LanguageTag -eq $SystemConfig.Locale }) {
                    Set-WinUILanguageOverride -Language $SystemConfig.Locale
                    Set-WinSystemLocale -SystemLocale $SystemConfig.Locale
                    Set-WinUserLanguageList $SystemConfig.Locale -Force
                    Set-Culture -CultureInfo $SystemConfig.Locale
                    
                    $script:restartRequired = $true
                    Write-SystemMessage -successMsg
                }
                else {
                    Write-Log "Invalid or unsupported locale: $($SystemConfig.Locale)" -Level Warning
                    Write-SystemMessage -errorMsg
                }
            }
            catch {
                Write-Log "Error setting system locale: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg -msg "Failed to set system locale"
            }
        }

        if ($SystemConfig.Timezone) {
            $currentTZ = (Get-TimeZone).Id

            Write-Log "Setting timezone to: $($SystemConfig.Timezone)" -Level Info
            Write-SystemMessage -msg "Setting timezone to" -value $SystemConfig.Timezone

            if ($currentTZ -ne $SystemConfig.Timezone) {
                try {
                    Set-TimeZone -Id $SystemConfig.Timezone
                    $newTZ = (Get-TimeZone).Id
                    if ($newTZ -eq $SystemConfig.Timezone) {
                        Write-SystemMessage -successMsg
                    }
                    else {
                        Write-Log "Failed to set timezone to: $($SystemConfig.Timezone)" -Level Error
                        Write-SystemMessage -errorMsg
                    }
                }
                catch {
                    Write-Log "Error setting timezone: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg -msg "Failed to set timezone. Check Log for details."
                }
            }
            else {
                Write-Log "Timezone is already set to: $($SystemConfig.Timezone)" -Level Warning
                Write-SystemMessage -warningMsg -msg "Timezone already set to" -value $SystemConfig.Timezone
            }
        }

        # Remote Desktop
        if ($SystemConfig.EnableRemoteDesktop -eq 'true') {
            Write-Log "Enabling Remote Desktop..." -Level Info
            Write-SystemMessage -msg "Enabling Remote Desktop..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
                Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to enable Remote Desktop: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($SystemConfig.EnableRemoteDesktop -eq 'false') {
            Write-Log "Disabling Remote Desktop..." -Level Info
            Write-SystemMessage -msg "Disabling Remote Desktop..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
                Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to disable Remote Desktop: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Windows Store
        if ($SystemConfig.DisableWindowsStore -eq 'true') {
            Write-Log "Disabling Windows Store..." -Level Info
            Write-SystemMessage -msg "Disabling Windows Store..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to disable Windows Store: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($SystemConfig.DisableWindowsStore -eq 'false') {
            Write-Log "Enabling Windows Store..."
            Write-SystemMessage -msg "Enabling Windows Store..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to enable Windows Store: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        if ($SystemConfig.DisableOneDrive -eq 'true') {
            Write-Log "Disabling OneDrive..." -Level Info
            Write-SystemMessage -msg "Disabling OneDrive."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
                Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Error disabling OneDrive: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($SystemConfig.DisableOneDrive -eq 'false') {
            Write-Log "Enabling OneDrive..." -Level Info
            Write-SystemMessage -msg "Enabling OneDrive."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Error enabling OneDrive: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        if ($SystemConfig.DisableCopilot -eq 'true') {
            Write-Log "Disabling Windows Copilot..." -Level Info
            Write-SystemMessage -msg "Disabling Windows Copilot."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "CopilotEnabled" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Error disabling Windows Copilot: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($SystemConfig.DisableCopilot -eq 'false') {
            Write-Log "Enabling Windows Copilot..." -Level Info
            Write-SystemMessage -msg "Enabling Windows Copilot."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "CopilotEnabled" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Error enabling Windows Copilot: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Show File Extensions
        if ($SystemConfig.ShowFileExtensions -eq 'true') {
            Write-SystemMessage -msg "Showing file extensions..."
            Write-Log "Showing file extensions..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to show file extensions: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($SystemConfig.ShowFileExtensions -eq 'false') {
            Write-SystemMessage -msg "Hiding file extensions..."
            Write-Log "Hiding file extensions..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to hide file extensions: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Show Hidden Files
        if ($SystemConfig.ShowHiddenFiles -eq 'true') {
            Write-SystemMessage -msg "Showing hidden files..."
            Write-Log "Showing hidden files..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to show hidden files: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($SystemConfig.ShowHiddenFiles -eq 'false') {
            Write-SystemMessage -msg "Hiding hidden files..."
            Write-Log "Hiding hidden files..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to hide hidden files: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Disable Setup Device Prompt
        if ($SystemConfig.DisableSetupDevicePrompt -eq 'true') {
            Write-SystemMessage -msg "Disabling Setup Device Prompt..."
            Write-Log "Disabling Setup Device Prompt..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagemen" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to disable Setup Device Prompt: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($SystemConfig.DisableSetupDevicePrompt -eq 'false') {
            Write-SystemMessage -msg "Enabling Setup Device Prompt..."
            Write-Log "Enabling Setup Device Prompt..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagemen" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to enable Setup Device Prompt: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
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

    Write-SystemMessage -title "Configuring Security Settings"

        try {

            # Windows Defender
            if ($SecurityConfig.DisableDefender -eq 'true') {
                Write-SystemMessage -msg "Disabling Windows Defender..."
                Write-Log "Disabling Windows Defender..." -Level Info
                try {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to disable Windows Defender: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
            elseif ($SecurityConfig.DisableDefender -eq 'false') {
                Write-SystemMessage -msg "Enabling Windows Defender..."
                Write-Log "Enabling Windows Defender..." -Level Info
                try {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 0
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to enable Windows Defender: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }

            # UAC Settings
            if ($SecurityConfig.DisableUAC -eq 'true') {
                Write-SystemMessage -msg "Disabling UAC..."
                Write-Log "Disabling UAC..." -Level Info
                try {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 0
                    Write-SystemMessage -successMsg
                    $script:restartRequired = $true
                }
                catch {
                    Write-Log "Failed to disable UAC: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
            elseif ($SecurityConfig.DisableUAC -eq 'false') {
                Write-SystemMessage -msg "Enabling UAC..."
                Write-Log "Enabling UAC..."-Level Info
                try {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 1
                    Write-SystemMessage -successMsg
                    $script:restartRequired = $true
                }
                catch {
                    Write-Log "Failed to enable UAC: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }

            # UAC Level Settings
            if ($SecurityConfig.UACLevel) {
                Write-SystemMessage -msg "Setting UAC level to" -value $SecurityConfig.UACLevel
                Write-Log "Setting UAC level to: $($SecurityConfig.UACLevel)" -Level Info
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
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to set UAC level: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            
            }

            # AutoPlay
            if ($SecurityConfig.DisableAutoPlay -eq 'true') {
                Write-SystemMessage -msg "Disabling AutoPlay..."
                Write-Log "Disabling AutoPlay..." -Level Info
                try {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to disable AutoPlay: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
            elseif ($SecurityConfig.DisableAutoPlay -eq 'false') {
                Write-SystemMessage -msg "Enabling AutoPlay..."
                Write-Log "Enabling AutoPlay..." -Level Info
                try {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 0
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to enable AutoPlay: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }

            # BitLocker
            if ($SecurityConfig.BitLocker.Enable -eq 'true') {
                Write-SystemMessage -msg "Configuring BitLocker for drive: " -value $SecurityConfig.BitLocker.Target
                Write-Log "Configuring BitLocker for drive: $($SecurityConfig.BitLocker.Target)" -Level Info
                try {
                    Enable-BitLocker -MountPoint $SecurityConfig.BitLocker.Target -EncryptionMethod XtsAes256 -UsedSpaceOnly
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to configure BitLocker: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
            elseif ($SecurityConfig.BitLocker.Enable -eq 'false') {
                Write-SystemMessage -msg "Disabling BitLocker for drive: " -value $SecurityConfig.BitLocker.Target
                Write-Log "Disabling BitLocker for drive: $($SecurityConfig.BitLocker.Target)" -Level Info
                try {
                    Disable-BitLocker -MountPoint $SecurityConfig.BitLocker.Target
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to disable BitLocker: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }

            Write-Log "Security configuration completed successfully" -Level Info
            return $true
        }
        catch {
            Write-Log "Error configuring security settings: $($_.Exception.Message)" -Level Error
            Write-SystemMessage -errorMsg -msg "Error configuring security settings"
            return $false
        }
    }


function Set-PrivacyConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$PrivacyConfig
    )
    
    Write-SystemMessage -title "Configuring Privacy Settings"

    try {
        # Telemetry
        if ($PrivacyConfig.DisableTelemetry -eq 'true') {
            Write-SystemMessage -msg "Disabling telemetry..."
            Write-Log "Disabling telemetry..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable telemetry: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableTelemetry -eq 'false') {
            Write-SystemMessage -msg "Enabling telemetry..."
            Write-Log "Enabling telemetry..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable telemetry: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # DiagTrack
        if ($PrivacyConfig.DisableDiagTrack -eq 'true') {
            Write-SystemMessage -msg "Disabling diagnostic tracking..."
            Write-Log "Disabling diagnostic tracking..." -Level Info
            try {
                Stop-Service "DiagTrack" -Force | Out-Null
                Set-Service "DiagTrack" -StartupType Disabled | Out-Null
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable diagnostic tracking: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableDiagTrack -eq 'false') {
            Write-SystemMessage -msg "Enabling diagnostic tracking..."
            Write-Log "Enabling diagnostic tracking..." -Level Info
            try {
                Set-Service "DiagTrack" -StartupType Automatic | Out-Null
                Start-Service "DiagTrack" | Out-Null
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable diagnostic tracking: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # App Privacy
        if ($PrivacyConfig.DisableAppPrivacy -eq 'true') {
            Write-SystemMessage -msg "Configuring app privacy settings..."
            Write-Log "Configuring app privacy settings..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Type String -Value "Deny"
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Type String -Value "Deny"
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to configure app privacy settings: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableAppPrivacy -eq 'false') {
            Write-SystemMessage -msg "Enabling app privacy settings..."
            Write-Log "Enabling app privacy settings..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Allow"
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Type String -Value "Allow"
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Type String -Value "Allow"
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable app privacy settings: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Start Menu Tracking
        if ($PrivacyConfig.DisableStartMenuTracking -eq 'true') {
            Write-SystemMessage -msg "Disabling Start Menu tracking..."
            Write-Log "Disabling Start Menu tracking..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Start Menu tracking: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableStartMenuTracking -eq 'false') {
            Write-SystemMessage -msg "Enabling Start Menu tracking..."
            Write-Log "Enabling Start Menu tracking..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable Start Menu tracking: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Activity History
        if ($PrivacyConfig.DisableActivityHistory -eq 'true') {
            Write-SystemMessage -msg "Disabling Activity History..."
            Write-Log "Disabling Activity History..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Activity History: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableActivityHistory -eq 'false') {
            Write-SystemMessage -msg "Enabling Activity History..."
            Write-Log "Enabling Activity History..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable Activity History: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Clipboard Data Collection
        if ($PrivacyConfig.DisableClipboardDataCollection -eq 'true') {
            Write-SystemMessage -msg "Disabling Clipboard data collection..."
            Write-Log "Disabling Clipboard data collection..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Clipboard data collection: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableClipboardDataCollection -eq 'false') {
            Write-SystemMessage -msg "Enabling Clipboard data collection..."
            Write-Log "Enabling Clipboard data collection..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable Clipboard data collection: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } 

        # Start Menu Suggestions
        if ($PrivacyConfig.DisableStartMenuSuggestions -eq 'true') {
            Write-SystemMessage -msg "Disabling Start Menu suggestions..."
            Write-Log "Disabling Start Menu suggestions..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Start Menu suggestions: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableStartMenuSuggestions -eq 'false') {
            Write-SystemMessage -msg "Enabling Start Menu suggestions..."
            Write-Log "Enabling Start Menu suggestions..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable Start Menu suggestions: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        Write-Log "Privacy configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring privacy settings: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Error configuring privacy settings"
        return $false
    }
}

function Install-Applications {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$AppConfig
    )

    Write-SystemMessage -title "Installing Applications"

    try {
        if (-not $AppConfig) {
            Write-Log "No applications to install" -Level Info
            return $true
        }

        $packageManager = $AppConfig.PackageManager
        if (-not $packageManager) {
            Write-Log "No package manager specified for installation" -Level Error
            Write-SystemMessage -errorMsg -msg "No package manager specified"
            return $false
        }

        Write-Log "Installing applications using $packageManager" -Level Info

        # Chocolatey Apps
        if ($packageManager -eq "Chocolatey") {
            # Check if Chocolatey is installed
            if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                Write-Log "Installing Chocolatey..." -Level Info
                Write-SystemMessage -msg "Installing Chocolatey..."
                try {
                    $installScript = {
                        Set-ExecutionPolicy Bypass -Scope Process -Force
                        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                    }
                    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command & {$installScript}" -Wait -WindowStyle Normal
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to install Chocolatey: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                    return $false
                }
            }

            # Refresh shell environment to get choco commands
            Write-Log "Refreshing environment variables after chocolatey installation." -Level Info
            try {
                $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            } catch {
                Write-Log "Failed to refresh shell environment: $($_.Exception.Message)" -Level Error 
            }

            # Install Chocolatey Apps
            foreach ($app in $AppConfig.App) {
                $appName = $app.InnerText.Trim()
                $version = $app.Version

                if ([string]::IsNullOrWhiteSpace($appName)) {
                    Write-Log "Empty application name found. Skipping..." -Level Warning
                    continue
                }

                Write-SystemMessage -msg "Installing" -value $appName
                Write-Log "Installing $appName..." -Level Info
                try {
                    if ($version) {
                        $result = Start-Process -FilePath "choco" -ArgumentList "install `"$appName`" --version $version -y" -Wait -NoNewWindow -PassThru
                    }
                    else {
                        $result = Start-Process -FilePath "choco" -ArgumentList "install `"$appName`" -y" -Wait -NoNewWindow -PassThru
                    }
                    
                    if ($result.ExitCode -eq 0) {
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "Failed to install $appName. Exit code: $($result.ExitCode)" -Level Error
                        Write-SystemMessage -errorMsg
                    }
                }
                catch {
                    $errorMessage = $_.Exception.Message
                    Write-Log "Failed to install $appName : $errorMessage" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
        }

        # Winget Apps
        if ($packageManager -eq "Winget") {
            # Check if winget is available
            if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                Write-Log "Winget is not installed. Please install App Installer from the Microsoft Store." -Level Error
                Write-SystemMessage -errorMsg -msg "Winget is not installed"
                return $false
            }

            # Install Winget Apps
            foreach ($app in $AppConfig.App) {
                $appName = $app.InnerText.Trim()
                $version = $app.Version

                if ([string]::IsNullOrWhiteSpace($appName)) {
                    Write-Log "Empty application name found. Skipping..." -Level Warning
                    continue
                }

                Write-SystemMessage -msg "Installing" -value $appName
                Write-Log "Installing $appName..." -Level Info
                try {
                    # Search for exact package first
                    $searchResult = winget search --exact --query $appName --accept-source-agreements | Out-String
                    if ($searchResult -notmatch $appName) {
                        Write-Log "Package $appName not found in winget repository" -Level Warning
                        Write-SystemMessage -warningMsg -msg "Package not found in repository"
                        continue
                    }

                    if ($version) {
                        $result = Start-Process -FilePath "winget" -ArgumentList "install --exact --id $appName --version $version --accept-source-agreements --accept-package-agreements" -Wait -NoNewWindow -PassThru
                    }
                    else {
                        $result = Start-Process -FilePath "winget" -ArgumentList "install --exact --id $appName --accept-source-agreements --accept-package-agreements" -Wait -NoNewWindow -PassThru
                    }
                    
                    if ($result.ExitCode -eq 0) {
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "Failed to install $appName. Exit code: $($result.ExitCode)" -Level Error
                        Write-SystemMessage -errorMsg
                    }
                }
                catch {
                    Write-Log "Failed to install $appName : $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
        }

        Write-Log "Application installation completed successfully"
        return $true
    }
    catch {
        Write-Log "Error installing applications: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to install applications. Check the log for details."
        return $false
    }
}

function Remove-Applications {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$AppConfig
    )

    Write-SystemMessage -title "Removing Applications"

    try {
        if (-not $AppConfig) {
            Write-Log "No applications to uninstall" -Level Info
            return $true
        }

        $packageManager = $AppConfig.PackageManager
        if (-not $packageManager) {
            Write-Log "No package manager specified for uninstallation" -Level Error
            Write-SystemMessage -errorMsg -msg "No package manager specified"
            return $false
        }

        Write-Log "Uninstalling applications using $packageManager" -Level Info

        # Winget Uninstall
        if ($packageManager -eq "Winget") {
            # Check if winget is available
            if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                Write-Log "Winget is not installed. Please install App Installer from the Microsoft Store." -Level Error
                Write-SystemMessage -errorMsg -msg "Winget is not installed"
                return $false
            }

            foreach ($app in $AppConfig.App) {
                $appName = $app.InnerText.Trim()

                if ([string]::IsNullOrWhiteSpace($appName)) {
                    Write-Log "Empty application name found. Skipping..." -Level Warning
                    continue
                }

                Write-SystemMessage -msg "Uninstalling" -value $appName
                Write-Log "Uninstalling $appName..." -Level Info
                try {
                    # Check if app is installed first
                    $listResult = winget list --exact --query $appName --accept-source-agreements | Out-String
                    if ($listResult -match $appName) {
                        $result = Start-Process -FilePath "winget" -ArgumentList "uninstall --exact --id $appName --accept-source-agreements" -Wait -NoNewWindow -PassThru
                        if ($result.ExitCode -eq 0) {
                            Write-SystemMessage -successMsg
                        } else {
                            Write-Log "Failed to uninstall $appName. Exit code: $($result.ExitCode)" -Level Error
                            Write-SystemMessage -errorMsg
                        }
                    }
                    else {
                        Write-Log "App $appName is not installed" -Level Info
                        Write-SystemMessage -warningMsg -msg "$appName is not installed on this system"
                    }
                }
                catch {
                    $errorMessage = $_.Exception.Message
                    Write-Log "Failed to uninstall $appName : $errorMessage" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
        }

        # Chocolatey Uninstall
        if ($packageManager -eq "Chocolatey") {
            # Check if Chocolatey is installed
            if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                Write-Log "Chocolatey is not installed" -Level Error
                Write-SystemMessage -errorMsg -msg "Chocolatey is not installed"
                return $false
            }

            foreach ($app in $AppConfig.App) {
                $appName = $app.InnerText.Trim()

                if ([string]::IsNullOrWhiteSpace($appName)) {
                    Write-Log "Empty application name found. Skipping..." -Level Warning
                    continue
                }

                Write-SystemMessage -msg "Uninstalling" -value $appName
                Write-Log "Uninstalling $appName..." -Level Info
                try {
                    # Check if app is installed first
                    $listResult = Start-Process -FilePath "choco" -ArgumentList "list $appName -e" -Wait -NoNewWindow -PassThru
                    if ($listResult.ExitCode -eq 0) {
                        $result = Start-Process -FilePath "choco" -ArgumentList "uninstall `"$appName`" -y" -Wait -NoNewWindow -PassThru
                        if ($result.ExitCode -eq 0) {
                            Write-SystemMessage -successMsg
                        } else {
                            Write-Log "Failed to uninstall $appName. Exit code: $($result.ExitCode)" -Level Error
                            Write-SystemMessage -errorMsg
                        }
                    }
                    else {
                        Write-Log "App $appName is not installed" -Level Info
                        Write-SystemMessage -warningMsg -msg "$appName is not installed on this system"
                    }
                }
                catch {
                    $errorMessage = $_.Exception.Message
                    Write-Log "Failed to uninstall $appName : $errorMessage" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
        }

        Write-Log "Application removal completed successfully"
        return $true
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Log "Error removing applications: $errorMessage" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to remove applications. Check the log for details."
        return $false
    }
}

function Set-EnvironmentVariables {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$EnvConfig
    )
    
    Write-SystemMessage -title "Setting Environment Variables"

    try {
        foreach ($variable in $EnvConfig.ChildNodes) {
            Write-Log "Setting environment variable: $($variable.Name) = $($variable.InnerText)" -Level Info
            Write-SystemMessage -msg "Setting environment variable" -value $variable.Name
            try {
                [System.Environment]::SetEnvironmentVariable($variable.Name, $variable.InnerText, [System.EnvironmentVariableTarget]::Machine)
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to set environment variable: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        Write-SystemMessage -successMsg
        return $true
    }
    catch {
        Write-Log "Error setting environment variables: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg
        return $false
    }
}

function Set-WindowsActivation {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$ActivationConfig
    )
    
    Write-SystemMessage -title "Windows Activation"

    try {
        $productKey = $ActivationConfig.ProductKey
        $version = $ActivationConfig.Version
        
        # Install product key
        if ($productKey) {
            Write-SystemMessage -msg "Activating Windows with product key..."
            Write-Log "Activating Windows with product key..." -Level Info
            slmgr.vbs /ipk $productKey
            Start-Sleep -Seconds 2
            slmgr.vbs /ato
            Write-SystemMessage -successMsg
        }
        return $true
    }
    catch {
        Write-Log "Error activating Windows: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg
        return $false
    }
}

function Set-WindowsUpdateConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$UpdateConfig
    )
    
    Write-SystemMessage -title "Configuring Windows Update"

    try {        
        # Auto Update Settings
        if ($UpdateConfig.AutomaticUpdates) {
            Write-SystemMessage -msg "Configuring automatic updates..."
            Write-Log "Setting automatic updates to: $($UpdateConfig.AutomaticUpdates)"
            try {
                if ($UpdateConfig.AutomaticUpdates -eq 'true') {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutomaticUpdates" -Type DWord -Value 0
                } elseif ($UpdateConfig.AutomaticUpdates -eq 'false') {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutomaticUpdates" -Type DWord -Value 1
                }
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to configure automatic updates: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Update Options (2=Notify, 3=Auto DL, 4=Auto DL and Install)
        if ($UpdateConfig.AUOptions) {
            Write-SystemMessage -msg "Setting update behavior..."
            Write-Log "Setting update options to: $($UpdateConfig.AUOptions)"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value $UpdateConfig.AUOptions
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to set update options: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Schedule Settings
        if ($UpdateConfig.ScheduledInstallDay -and $UpdateConfig.ScheduledInstallTime) {
            Write-SystemMessage -msg "Configuring update schedule..."
            Write-Log "Setting update schedule - Day: $($UpdateConfig.ScheduledInstallDay), Time: $($UpdateConfig.ScheduledInstallTime)"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Type DWord -Value $UpdateConfig.ScheduledInstallDay
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Type DWord -Value $UpdateConfig.ScheduledInstallTime
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to set update schedule: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Auto Install Minor Updates
        if ($UpdateConfig.AutoInstallMinorUpdates -eq 'true') {
            Write-SystemMessage -msg "Enabling automatic minor updates..."
            Write-Log "Enabling automatic minor updates..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutoInstallMinorUpdates" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable automatic minor updates: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($UpdateConfig.AutoInstallMinorUpdates -eq 'false') {
            Write-SystemMessage -msg "Disabling automatic minor updates..."
            Write-Log "Disabling automatic minor updates..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutoInstallMinorUpdates" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable automatic minor updates: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        Write-Log "Windows Update configuration completed successfully"

        return $true
    }
    catch {
        Write-Log "Error configuring Windows Update: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to configure Windows Update. Check the log for details."
        return $false
    }
}

function Set-ScheduledTasksConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$TasksConfig
    )
    
    Write-SystemMessage -title "Configuring Scheduled Tasks"

    try {
        
        foreach ($task in $TasksConfig.Task) {
            Write-SystemMessage -msg "Importing task: " -value $task.Name
            Write-Log "Importing task: $($task.Name)" -Level Info
            
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
                    Write-Log "Task imported successfully: $($task.Name)" -Level Info
                    Write-SystemMessage -successMsg
                } else {
                    Write-Log "Task XML file not found: $taskPath" -Level Warning
                    Write-SystemMessage -errorMsg -msg "Task XML file not found" -value $taskPath
                }
            } catch {
                Write-Log "Failed to import task $($task.Name): $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        Write-Log "Scheduled tasks configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring scheduled tasks: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to configure scheduled tasks. Check the log for details."
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
    
    Write-SystemMessage -title "Installing Fonts"

    try {
        $tempDownloadFolder = "$env:TEMP\google_fonts"
        $script:tempFiles += $tempDownloadFolder

        foreach ($fontName in $FontConfig.Font) {
            # Correct the font names for the GitHub repository
            $correctFontName = $fontName -replace "\+", ""

            # Check if the font is already installed
            if (Test-FontInstalled -FontName $correctFontName) {
                Write-Log "Font $correctFontName is already installed. Skipping..." -Level Info
                Write-SystemMessage -msg "Font $correctFontName is already installed. Skipping..."
                continue
            }

            Write-SystemMessage -msg "Installing" -value $correctFontName
            Write-Log "Downloading & Installing $correctFontName from Google Fonts GitHub repository..." -Level Info

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

                Write-Log "Font installed: $correctFontName" -Level Info
                Write-SystemMessage -successMsg

            } catch {
                Write-Log "Failed to install font $correctFontName : $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
                continue
            }
        }

        Write-Log "Font installation completed successfully"
        return $true
    }
    catch {
        Write-Log "Error installing fonts: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to install fonts. Check the log for details."
        return $false
    }
    finally {
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
    
    Write-SystemMessage -title "Configuring Taskbar"

    try {
        
        # Taskbar Alignment (Left = 0, Center = 1)
        if ($TaskbarConfig.TaskbarAlignment) {
            Write-Log "Setting taskbar alignment to: $($TaskbarConfig.TaskbarAlignment)" -Level Info
            Write-SystemMessage -msg "Setting taskbar alignment to" -value $($TaskbarConfig.TaskbarAlignment)
            $alignmentValue = if ($TaskbarConfig.TaskbarAlignment -eq 'Left') { 0 } else { 1 }
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type DWord -Value $alignmentValue
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to set taskbar alignment: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Meet Now
        if ($TaskbarConfig.DisableMeetNow -eq 'true') {
            Write-Log "Disabling Meet Now..." -Level Info
            Write-SystemMessage -msg "Disabling Meet Now..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Meet Now: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($TaskbarConfig.DisableMeetNow -eq 'false') {
            Write-Log "Enabling Meet Now..." -Level Info
            Write-SystemMessage -msg "Enabling Meet Now..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable Meet Now: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Widgets
        if ($TaskbarConfig.DisableWidgets -eq 'true') {
            Write-Log "Disabling Widgets..." -Level Info
            Write-SystemMessage -msg "Disabling Widgets..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Widgets: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($TaskbarConfig.DisableWidgets -eq 'false') {
            Write-Log "Enabling Widgets..." -Level Info
            Write-SystemMessage -msg "Enabling Widgets..."
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable Widgets: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Task View
        if ($TaskbarConfig.DisableTaskView -eq 'true') {
            Write-Log "Disabling Task View button..." -Level Info
            Write-SystemMessage -msg "Disabling Task View button..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Task View button: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($TaskbarConfig.DisableTaskView -eq 'false') {
            Write-Log "Enabling Task View button..."
            Write-SystemMessage -msg "Enabling Task View button..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable Task View button: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Search
        if ($TaskbarConfig.DisableSearch -eq 'true') {
            Write-Log "Disabling Search icon..."
            Write-SystemMessage -msg "Disabling Search icon..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSearchBox" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Search icon: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($TaskbarConfig.DisableSearch -eq 'false') {
            Write-Log "Enabling Search icon..."
            Write-SystemMessage -msg "Enabling Search icon..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSearchBox" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable Search icon: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
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
        Write-SystemMessage -errorMsg -msg "Failed to configure taskbar. Check the logs for more details."
        return $false
    }
}

# Function to configure the power settings
function Set-PowerConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$PowerConfig
    )
    
    Write-SystemMessage -title "Configuring Power Settings"

    try {

        # Power Plan
        if ($PowerConfig.PowerPlan) {
            Write-Log "Setting power plan to: $($PowerConfig.PowerPlan)"
            Write-SystemMessage -msg "Setting power plan to" -value $PowerConfig.PowerPlan

            $guid = switch ($PowerConfig.PowerPlan) {
                "Balanced" { "381b4222-f694-41f0-9685-ff5bb260df2e" }
                "HighPerformance" { "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" }
                "PowerSaver" { "a1841308-3541-4fab-bc81-f71556f20b4a" }
                default {
                    Write-Log "Invalid power plan specified: $($PowerConfig.PowerPlan)" -Level Warning
                    Write-SystemMessage -errorMsg -msg "Invalid power plan specified"
                    return $false
                }
            }
            
            try {
                powercfg /setactive $guid
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to set power plan: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
                return $false
            }
        }

        # Sleep Settings
        if ($PowerConfig.DisableSleep -eq 'true') {
            Write-Log "Disabling sleep..." -Level Info
            Write-SystemMessage -msg "Disabling sleep..."

            try {
                powercfg /change standby-timeout-ac 0
                powercfg /change standby-timeout-dc 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable sleep: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }

        } elseif ($PowerConfig.DisableSleep -eq 'false') {
            Write-Log "Enabling sleep..." -Level Info
            Write-SystemMessage -msg "Enabling sleep..."
            
            try {
                powercfg /change standby-timeout-ac 30
                powercfg /change standby-timeout-dc 30
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable sleep: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Hibernate Settings
        if ($PowerConfig.DisableHibernate -eq 'true') {
            Write-Log "Disabling hibernate..." -Level Info
            Write-SystemMessage -msg "Disabling hibernate..."
            try {
                powercfg /hibernate off
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable hibernate: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PowerConfig.DisableHibernate -eq 'false') {
            Write-Log "Enabling hibernate..." -Level Info
            Write-SystemMessage -msg "Enabling hibernate..."
            try {
                powercfg /hibernate on
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable hibernate: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Timeouts (if specified)
        if ($PowerConfig.MonitorTimeout) {
            Write-Log "Setting monitor timeout to: $($PowerConfig.MonitorTimeout) minutes" -Level Info
            Write-SystemMessage -msg "Setting monitor timeout to" -value "$($PowerConfig.MonitorTimeout) minutes"
            powercfg /change monitor-timeout-ac $PowerConfig.MonitorTimeout
            powercfg /change monitor-timeout-dc $PowerConfig.MonitorTimeout
            Write-SystemMessage -successMsg
        }

        # Fast Startup
        if ($PowerConfig.DisableFastStartup -eq 'true') {
            Write-SystemMessage -msg "Disabling fast startup..."
            Write-Log "Disabling fast startup..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable fast startup: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PowerConfig.DisableFastStartup -eq 'false') {
            Write-SystemMessage -msg "Enabling fast startup..."
            Write-Log "Enabling fast startup..." -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable fast startup: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        Write-Log "Power configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring power settings: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to configure power settings. Check the logs for more details."
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
        
        # Process registry additions
        if ($RegistryConfig.Add) {
           
            Write-SystemMessage -title "Adding Registry Entries"

            foreach ($entry in $RegistryConfig.Add.Entry) {
                # Expand environment variables in the value
                $expandedValue = $ExecutionContext.InvokeCommand.ExpandString($entry.Value)

                Write-SystemMessage -msg "Adding registry entry" -value "Path=$($entry.Path), Name=$($entry.Name)"
                Write-Log "Adding registry entry: Path=$($entry.Path), Name=$($entry.Name), Type=$($entry.Type), Value=$expandedValue" -Level Info

                try {
                    if (-not (Test-Path $entry.Path)) {
                        New-Item -Path $entry.Path -Force | Out-Null
                        Write-Log "Created registry path: $($entry.Path)" -Level Info
                    }

                    Set-ItemProperty -Path $entry.Path -Name $entry.Name -Value $expandedValue -Type $entry.Type -Force
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to add registry entry: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                    continue
                }
            }
        }

        # Process registry removals
        if ($RegistryConfig.Remove) {
            
            Write-SystemMessage -title "Removing Registry Entries"

            foreach ($entry in $RegistryConfig.Remove.Entry) {
                Write-SystemMessage -msg "Removing registry entry" -value "Path=$($entry.Path), Name=$($entry.Name)"
                Write-Log "Removing registry entry: Path=$($entry.Path), Name=$($entry.Name)" -Level Info

                try {
                    if (Test-Path $entry.Path) {
                        Remove-ItemProperty -Path $entry.Path -Name $entry.Name -Force -ErrorAction Stop
                        Write-SystemMessage -successMsg
                    }
                    else {
                        Write-Log "Registry path not found: $($entry.Path)" -Level Warning
                        Write-SystemMessage -errorMsg -msg "Registry path not found"
                    }
                } catch {
                    Write-Log "Failed to remove registry entry: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                    continue
                }
            }
        }

        Write-Log "Registry modifications completed successfully" -Level Info
        return $true
    }
    catch {
        Write-Log "Error modifying registry entries: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to modify registry entries. Check the logs for more details."
        return $false
    }
}

# Function to configure Windows features
function Set-WindowsFeaturesConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$FeaturesConfig
    )
    
    Write-SystemMessage -title "Configuring Windows Features"

    try {

        # Get list of available Windows features
        $availableFeatures = Get-WindowsOptionalFeature -Online | Select-Object -ExpandProperty FeatureName

        foreach ($feature in $FeaturesConfig.Feature) {
            # Validate feature exists
            if ($feature.Name -notin $availableFeatures) {
                Write-Log "Feature not found: $($feature.Name)" -Level Error
                Write-SystemMessage -errorMsg -msg "Feature not found" -value "$($feature.Name)"
                continue
            }

    
            try {
                switch ($feature.State.ToLower()) {
                    'enabled' {
                        Write-Log "Enabling feature: $($feature.Name)"
                        Write-SystemMessage -msg "Enabling feature" -value $feature.Name
                        $currentState = Get-WindowsOptionalFeature -Online -FeatureName $feature.Name
                        if ($currentState.State -eq 'Enabled') {
                            Write-Log "Feature $($feature.Name) is already enabled" -Level Warning
                            Write-SystemMessage -warningMsg -msg "Feature already enabled"
                            continue
                        }
                        $result = Enable-WindowsOptionalFeature -Online -FeatureName $feature.Name -NoRestart -WarningAction SilentlyContinue | Out-Null
                        if ($result.RestartNeeded) {
                            $script:restartRequired = $true
                            Write-Log "Restart will be required for feature: $($feature.Name)"
                        }
                        Write-SystemMessage -successMsg
                    }
                    'disabled' {
                        Write-Log "Disabling feature: $($feature.Name)"
                        Write-SystemMessage -msg "Disabling feature" -value $feature.Name
                        $currentState = Get-WindowsOptionalFeature -Online -FeatureName $feature.Name
                        if ($currentState.State -eq 'Disabled') {
                            Write-Log "Feature $($feature.Name) is already disabled" -Level Warning
                            Write-SystemMessage -warningMsg -msg "Feature already disabled"
                            continue
                        }
                        $result = Disable-WindowsOptionalFeature -Online -FeatureName $feature.Name -NoRestart -WarningAction SilentlyContinue | Out-Null
                        if ($result.RestartNeeded) {
                            $script:restartRequired = $true
                            Write-Log "Restart will be required for feature: $($feature.Name)"
                        }
                        Write-SystemMessage -successMsg
                    }
                    default {
                        Write-Log "Invalid state specified for feature $($feature.Name): $($feature.State)" -Level Warning
                        Write-SystemMessage -errorMsg -msg "Invalid state specified for feature: $($feature.Name)"
                    }
                }
            } catch {
                $errorMsg = "Failed to configure feature $($feature.Name): $($_.Exception.Message)"
                Write-Log $errorMsg -Level Error
                Write-SystemMessage -errorMsg -msg $errorMsg
                if ($_.Exception.Message -match "restart") {
                    $script:restartRequired = $true
                }
            }
        }

        Write-Log "Windows features configuration completed successfully" -Level Info
        return $true
    }
    catch {
        Write-Log "Error configuring Windows features: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to configure Windows features. Check the logs for more details."
        return $false
    }
}

# Function to configure Google products
function Set-GoogleConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$GoogleConfig
    )

    Write-SystemMessage -title "Configuring Google Workspace"

    try {

        # Google Drive
        if ($GoogleConfig.InstallGoogleDrive -eq 'true') {
            if (Test-ProgramInstalled 'Google Drive') {
                Write-Log "Google Drive already installed. Skipping..." -Level Info
                return $true
            }

            Write-Log "Installing Google Drive..." -Level Info
            Write-SystemMessage -msg "Installing Google Drive..."

            try {
                $driveSetupUrl = "https://dl.google.com/drive-file-stream/GoogleDriveSetup.exe"
                $driveSetupPath = Join-Path $env:TEMP "GoogleDriveSetup.exe"
                $script:tempFiles += $driveSetupPath
                
                Invoke-WebRequest -Uri $driveSetupUrl -OutFile $driveSetupPath | Out-Null
                Start-Process -FilePath $driveSetupPath -ArgumentList "--silent" -Wait | Out-Null
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to install Google Drive: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }

        }
        
        if ($GoogleConfig.InstallGoogleDrive -eq 'false') {
            Write-Log "Uninstalling Google Drive..." -Level Info
            Write-SystemMessage -msg "Uninstalling Google Drive..."
            try {
                $uninstallString = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
                    Where-Object { $_.DisplayName -like "*Google Drive*" }).UninstallString
                if ($uninstallString) {
                    Start-Process -FilePath $uninstallString -ArgumentList "/silent /uninstall" -Wait | Out-Null
                    Write-SystemMessage -successMsg
                }
            } catch {
                Write-Log "Failed to uninstall Google Drive: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Google Chrome
        if ($GoogleConfig.InstallGoogleChrome -eq 'true') {
            if (Test-ProgramInstalled 'Google Chrome') {
                Write-Log "Google Chrome already installed. Skipping..." -Level Info
                return $true
            }

            Write-Log "Installing Google Chrome..." -Level Info
            Write-SystemMessage -msg "Installing Google Chrome..."
            
            try {
                $chromeSetupUrl = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
                $chromeSetupPath = Join-Path $env:TEMP "chrome_installer.exe"
                $script:tempFiles += $chromeSetupPath
                
                Invoke-WebRequest -Uri $chromeSetupUrl -OutFile $chromeSetupPath | Out-Null
                Start-Process -FilePath $chromeSetupPath -ArgumentList "/silent /install" -Wait | Out-Null
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to install Google Chrome: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        
        if ($GoogleConfig.InstallGoogleChrome -eq 'false') {
            Write-Log "Uninstalling Google Chrome..." -Level Info
            Write-SystemMessage -msg "Uninstalling Google Chrome..."
            try {
                $uninstallString = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
                    Where-Object { $_.DisplayName -like "*Google Chrome*" }).UninstallString
                if ($uninstallString) {
                    Start-Process -FilePath $uninstallString -ArgumentList "--uninstall --force-uninstall" -Wait | Out-Null
                    Write-SystemMessage -successMsg
                }
            } catch {
                Write-Log "Failed to uninstall Google Chrome: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Google Credential Provider for Windows (GCPW)
        if ($GoogleConfig.InstallGCPW -eq 'true') {
            if (-not $GoogleConfig.EnrollmentToken) {
                Write-Log "GCPW installation skipped - EnrollmentToken is required but was not provided" -Level Error
                Write-SystemMessage -errorMsg -msg "GCPW installation requires an EnrollmentToken in the configuration. Please fix your configuration file."
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
                Write-Log "Installing Google Credential Provider for Windows (GCPW)..." -Level Info
                Write-SystemMessage -msg "Installing Google Credential Provider for Windows (GCPW)..."
                
                try {
                    Invoke-WebRequest -Uri $gcpwUrl -OutFile "$env:TEMP\$gcpwFileName" | Out-Null
                    Write-Log "GCPW installer downloaded successfully" -Level Info
                } catch {
                    Write-Log "Failed to download GCPW installer: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg -msg "Failed to download GCPW installer: $($_.Exception.Message)"
                    return $false
                }
    
                try {
                    $arguments = "/i ""$env:TEMP\$gcpwFileName"" /quiet"
                    $installProcess = Start-Process msiexec.exe -ArgumentList $arguments -PassThru -Wait | Out-Null
    
                    if ($installProcess.ExitCode -eq 0) {
                        Write-Log "GCPW Installation completed successfully!" -Level Info
                        Write-SystemMessage -successMsg

                        # Set the required EnrollmentToken
                        Set-RegistryModification -action add -path "HKLM:\SOFTWARE\Policies\Google\CloudManagement" -name "EnrollmentToken" -type "String" -value $GoogleConfig.EnrollmentToken | Out-Null
                        
                        # Only set domains_allowed_to_login if it was provided
                        if ($GoogleConfig.DomainsAllowedToLogin) {
                            Set-RegistryModification -action add -path "HKLM:\Software\Google\GCPW" -name "domains_allowed_to_login" -type "String" -value $GoogleConfig.DomainsAllowedToLogin | Out-Null
                            Write-Log 'Domains allowed to login has been set successfully' -Level Info
                        } else {
                            Write-Log 'DomainsAllowedToLogin not provided. Skipping setting domains.' -Level Info
                        }
                    } else {
                        Write-Log "Failed to install GCPW. $($_.Exception.Message)" -Level Error
                        Write-SystemMessage -errorMsg
                    }
                } finally {
                    Remove-Item -Path "$env:TEMP\$gcpwFileName" -Force -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }

        if ($GoogleConfig.InstallGCPW -eq 'false') {
            Write-Log "Uninstalling Google Credential Provider for Windows (GCPW)..." -Level Info
            Write-SystemMessage -msg "Uninstalling Google Credential Provider for Windows (GCPW)..."
            try {
                $uninstallString = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
                    Where-Object { $_.DisplayName -like "*Google Credential Provider*" }).UninstallString
                if ($uninstallString) {
                    Start-Process msiexec.exe -ArgumentList "/x $uninstallString /quiet" -Wait | Out-Null
                    Write-SystemMessage -successMsg
                }
            } catch {
                Write-Log "Failed to uninstall GCPW: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Allowed Domains
        if ($GoogleConfig.DomainsAllowedToLogin) {
            Write-Log "Setting allowed domains..." -Level Info
            Write-SystemMessage -msg "Setting allowed domains..."
            try {
                Set-RegistryModification -action add -path "HKLM:\SOFTWARE\Policies\Google\Chrome" -name "AuthServerAllowlist" -type "String" -value $GoogleConfig.DomainsAllowedToLogin
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to set allowed domains: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        Write-Log "Google configuration completed successfully" -Level Info
        return $true
    }
    catch {
        Write-Log "Error configuring Google products: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to configure Google products. Check the logs for more details."
        return $false
    }
}

# Function to configure Microsoft Office
function Set-OfficeConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$OfficeConfig
    )
    
    Write-SystemMessage -title "Configuring Microsoft Office"

    try {
        
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
        Write-SystemMessage -msg "Downloading Office Deployment Tool..."
        Write-Log "Downloading Office Deployment Tool..."
        
        $odtUrl = "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_16731-20398.exe"
        $odtPath = Join-Path $env:TEMP "ODT.exe"
        $script:tempFiles += $odtPath
        
        try {
            Invoke-WebRequest -Uri $odtUrl -OutFile $odtPath | Out-Null
            Write-SystemMessage -successMsg
        } catch {
            Write-Log "Failed to download Office Deployment Tool: $($_.Exception.Message)" -Level Error
            Write-SystemMessage -errorMsg
            return $false
        }

        # Extract ODT
        Write-SystemMessage -msg "Extracting Office Deployment Tool..."
        Write-Log "Extracting Office Deployment Tool..."
        try {
            Start-Process -FilePath $odtPath -ArgumentList "/quiet /extract:$env:TEMP\ODT" -Wait | Out-Null
            Write-SystemMessage -successMsg
        } catch {
            Write-Log "Failed to extract Office Deployment Tool: $($_.Exception.Message)" -Level Error
            Write-SystemMessage -errorMsg
            return $false
        }

        # Install Office
        Write-SystemMessage -msg "Installing Microsoft Office..."
        Write-Log "Installing Microsoft Office..."
        $setupPath = Join-Path $env:TEMP "ODT\setup.exe"
        try {
            Start-Process -FilePath $setupPath -ArgumentList "/configure `"$configPath`"" -Wait | Out-Null
            Write-SystemMessage -successMsg
        } catch {
            Write-Log "Failed to install Microsoft Office: $($_.Exception.Message)" -Level Error
            Write-SystemMessage -errorMsg
            return $false
        }

        # Activate Office if license key provided
        if ($OfficeConfig.LicenseKey) {
            Write-SystemMessage -msg "Activating Microsoft Office..."
            Write-Log "Activating Microsoft Office..."
            
            $osppPath = "${env:ProgramFiles}\Microsoft Office\Office16\OSPP.VBS"
            if (Test-Path $osppPath) {
                try {
                    cscript $osppPath /inpkey:$($OfficeConfig.LicenseKey) | Out-Null
                    Start-Sleep -Seconds 2
                    cscript $osppPath /act | Out-Null
                    Write-SystemMessage -successMsg
                } catch {
                    Write-Log "Failed to activate Office: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            } else {
                Write-Log "Office activation path not found: $osppPath" -Level Warning
                Write-SystemMessage -errorMsg -msg "Office activation path not found" -value $osppPath
            }
        }

        Write-Log "Office configuration completed successfully" -Level Info
        return $true
    }
    catch {
        Write-Log "Error configuring Office: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to configure Microsoft Office. Check the log for more details."
        return $false
    }
}

# Function to configure theme settings
function Set-ThemeConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$ThemeConfig
    )

    Write-SystemMessage -title "Configuring Theme Settings"
    
    try {

        # Theme Mode (Dark/Light)
        if ($ThemeConfig.DarkMode) {
            if ($ThemeConfig.DarkMode -eq 'true') {
                Write-Log "Enabling dark mode..." -Level Info
                Write-SystemMessage -msg "Enabling dark mode..."
                try {
                    Set-RegistryModification -action add -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -name "AppsUseLightTheme" -type "DWord" -value 0
                    Set-RegistryModification -action add -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -name "SystemUsesLightTheme" -type "DWord" -value 0
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to enable dark mode: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
            elseif ($ThemeConfig.DarkMode -eq 'false') {
                Write-Log "Enabling light mode..." -Level Info
                Write-SystemMessage -msg "Enabling light mode..."
                try {
                    Set-RegistryModification -action add -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -name "AppsUseLightTheme" -type "DWord" -value 1
                    Set-RegistryModification -action add -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -name "SystemUsesLightTheme" -type "DWord" -value 1
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to enable light mode: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
        }

        # Transparency Effects
        if ($ThemeConfig.TransparencyEffects) {
            if ($ThemeConfig.TransparencyEffects -eq 'false') {
                Write-Log "Disabling transparency effects..." -Level Info
                Write-SystemMessage -msg "Disabling transparency effects..."
                try {
                    Set-RegistryModification -action add -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -name "EnableTransparency" -type "DWord" -value 0
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to disable transparency effects: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
            elseif ($ThemeConfig.TransparencyEffects -eq 'true') {
                Write-Log "Enabling transparency effects..." -Level Info
                Write-SystemMessage -msg "Enabling transparency effects..."
                try {
                    Set-RegistryModification -action add -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -name "EnableTransparency" -type "DWord" -value 1
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to enable transparency effects: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
        }

        # Wallpaper
        if ($ThemeConfig.WallpaperPath) {
            Write-Log "Setting wallpaper from: $ThemeConfig.WallpaperPath" -Level Info
            Write-SystemMessage -msg "Setting wallpaper from" -value $ThemeConfig.WallpaperPath

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
                        Write-Log "Wallpaper downloaded successfully to: $wallpaperPath" -Level Info
                    }
                    catch {
                        Write-Log "Failed to download wallpaper from: $wallpaperPath" -Level Error
                        Write-SystemMessage -errorMsg -msg "Failed to download wallpaper from" -value $wallpaperPath
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
                
                Write-Log "Wallpaper set successfully." -Level Info
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Error setting wallpaper: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Lock Screen
        if ($ThemeConfig.LockScreenPath) {
            Write-Log "Setting lock screen from: $ThemeConfig.LockScreenPath" -Level Info
            Write-SystemMessage -msg "Setting lock screen from" -value $ThemeConfig.LockScreenPath
            try {
                $lockScreenPath = $ThemeConfig.LockScreenPath
                if ($lockScreenPath -match "^https?://") {
                    try {
                        Write-Log "Downloading lock screen from: $lockScreenPath" -Level Info
                    
                        # Extract filename from URL or use a default
                        $lockScreenFileName = [System.IO.Path]::GetFileName($lockScreenPath)
                        if ([string]::IsNullOrEmpty($lockScreenFileName)) {
                            $lockScreenFileName = "lockscreen$(([System.IO.Path]::GetExtension($lockScreenPath)))"
                        }
                        
                        Invoke-WebRequest -Uri $lockScreenPath -OutFile "$env:TEMP\$lockScreenFileName" | Out-Null

                        $lockScreenPath = "$env:TEMP\$lockScreenFileName"
                        $script:tempFiles += $lockScreenPath
                        Write-Log "Lock screen downloaded successfully to: $lockScreenPath" -Level Info
                    }
                    catch {
                        Write-Log "Failed to download lock screen from: $lockScreenPath" -Level Error
                        Write-SystemMessage -errorMsg -msg "Failed to download lock screen from" -value $lockScreenPath
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
        
                Write-Log "Lock screen set successfully." -Level Info
                Write-SystemMessage -successMsg
            }
        }
            catch {
                Write-Log "Error setting lock screen: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Desktop Icon Size
        if ($ThemeConfig.DesktopIconSize) {
            Write-SystemMessage -msg "Setting desktop icon size..."
            Write-Log "Setting desktop icon size..." -Level Info
            try {
                $sizeValue = switch ($ThemeConfig.DesktopIconSize) {
                    "Small" { 16 }  # Increased from 0
                    "Medium" { 24 } # Increased from 1 
                    "Large" { 32 }  # Increased from 2
                    default {
                        Write-Log "Invalid desktop icon size specified: $($ThemeConfig.DesktopIconSize). Using Medium." -Level Warning
                        64 # Increased default size
                    }
                }
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" -Name "IconSize" -Type DWord -Value $sizeValue
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to set desktop icon size: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Restart Explorer to apply changes
        Write-Log "Restarting Explorer to apply taskbar changes..."
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        Start-Process explorer

        Write-Log "Theme configuration completed successfully"
        return $true
    
}
    catch {
        Write-Log "Error configuring theme settings: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to configure theme settings. Check the log for more details."
        return $false
    }
}

# Function to apply system tweaks
function Set-TweaksConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$TweaksConfig
    )
    
    Write-SystemMessage -title "Applying System Tweaks"

    try {

        # Classic Right-Click Menu
        if ($TweaksConfig.ClassicRightClickMenu -eq 'true') {
            Write-Log "Enabling classic right-click menu..." -Level Info
            Write-SystemMessage -msg "Enabling classic right-click menu..."
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Type String -Value ""
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable classic right-click menu: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($TweaksConfig.ClassicRightClickMenu -eq 'false') {
            Write-Log "Disabling classic right-click menu..." -Level Info
            Write-SystemMessage -msg "Disabling classic right-click menu..."
            try {
                Remove-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable classic right-click menu: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # God Mode
        if ($TweaksConfig.EnableGodMode -eq 'true') {
            Write-Log "Creating God Mode folder..." -Level Info
            Write-SystemMessage -msg "Creating God Mode folder..."
            try {
                $godModePath = Join-Path $env:USERPROFILE "Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
                if (-not (Test-Path $godModePath)) {
                    New-Item -Path $godModePath -ItemType Directory -Force | Out-Null
                    Write-SystemMessage -successMsg
                }
            } catch {
                Write-Log "Failed to create God Mode folder: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($TweaksConfig.EnableGodMode -eq 'false') {
            Write-Log "Removing God Mode folder..." -Level Info
            Write-SystemMessage -msg "Removing God Mode folder..."
            try {
                $godModePath = Join-Path $env:USERPROFILE "Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
                if (Test-Path $godModePath) {
                    Remove-Item -Path $godModePath -Force -Recurse | Out-Null
                    Write-SystemMessage -successMsg
                }
            } catch {
                Write-Log "Failed to remove God Mode folder: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        Write-Log "System tweaks applied successfully" -Level Info
        return $true
    }
    catch {
        Write-Log "Error applying system tweaks: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to apply system tweaks. Check the log for more details."
        return $false
    }
}

# Function to configure network settings
function Set-NetworkConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$NetworkConfig
    )
    
    Write-SystemMessage -title "Configuring Network Settings"

    try {

        # Network Discovery
        if ($NetworkConfig.NetworkDiscovery -eq 'true') {
            
            Write-SystemMessage -msg "Enabling Network Discovery..."
            Write-Log "Enabling Network Discovery..." -Level Info
        
            # Check if Network Discovery is already enabled
            try {
                $discoveryRules = Get-NetFirewallRule -Group "@FirewallAPI.dll,-32752" 
                $smbRule = Get-NetFirewallRule -Name "FPS-SMB-In-TCP"
                
                if (($discoveryRules | Where-Object {$_.Enabled -eq $true}).Count -eq $discoveryRules.Count -and 
                    $smbRule.Enabled -eq $true) {
                    Write-Log "Network Discovery is already enabled" -Level Warning
                    Write-SystemMessage -warningMsg -msg "Network Discovery is already enabled"
                    return
                }
            } catch {
                Write-Log "Error checking Network Discovery status: $($_.Exception.Message)" -Level Error
            }
        
            # Enable Network Discovery
            try {
                Get-NetFirewallRule -Group "@FirewallAPI.dll,-32752" | Set-NetFirewallRule -Profile Private -Enabled True
                Set-NetFirewallRule -Name "FPS-SMB-In-TCP" -Enabled True
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable Network Discovery: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } 
        
        if ($NetworkConfig.NetworkDiscovery -eq 'false') {

            Write-Log "Disabling Network Discovery..." -Level Info
            Write-SystemMessage -msg "Disabling Network Discovery..."

            # Check if Network Discovery is already disabled
            try {
                $discoveryRules = Get-NetFirewallRule -Group "@FirewallAPI.dll,-32752" 
                $smbRule = Get-NetFirewallRule -Name "FPS-SMB-In-TCP"
                
                if (($discoveryRules | Where-Object {$_.Enabled -eq $false}).Count -eq $discoveryRules.Count -and 
                    $smbRule.Enabled -eq $false) {
                    Write-Log "Network Discovery is already disabled" -Level Warning
                    Write-SystemMessage -warningMsg -msg "Network Discovery is already disabled"
                    return
                }
            } catch {
                Write-Log "Error checking Network Discovery status: $($_.Exception.Message)" -Level Error
            }

            # Disable Network Discovery
            try {
                Get-NetFirewallRule -Group "@FirewallAPI.dll,-32752" | Set-NetFirewallRule -Profile Private -Enabled False
                Set-NetFirewallRule -Name "FPS-SMB-In-TCP" -Enabled False
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Network Discovery: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # File and Printer Sharing
        if ($NetworkConfig.FileAndPrinterSharing -eq 'true') {
            Write-Log "Enabling File and Printer Sharing..." -Level Info
            Write-SystemMessage -msg "Enabling File and Printer Sharing..."

            # Check if File and Printer Sharing is already enabled
            try {
                $fileSharingRule = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing"
                if ($fileSharingRule.Enabled -eq $true) {
                    Write-Log "File and Printer Sharing is already enabled" -Level Warning
                    Write-SystemMessage -warningMsg -msg "File and Printer Sharing is already enabled"
                    return
                }
            } catch {
                Write-Log "Error checking File and Printer Sharing status: $($_.Exception.Message)" -Level Error
            }

            try {
                Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable File and Printer Sharing: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
            
        } 
        
        if ($NetworkConfig.FileAndPrinterSharing -eq 'false') {
            
            Write-Log "Disabling File and Printer Sharing..." -Level Info
            Write-SystemMessage -msg "Disabling File and Printer Sharing..."

            # Check if File and Printer Sharing is already disabled
            try {
                $fileSharingRule = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing"
                if ($fileSharingRule.Enabled -eq $false) {
                    Write-Log "File and Printer Sharing is already disabled" -Level Warning
                    Write-SystemMessage -warningMsg -msg "File and Printer Sharing is already disabled"
                    return
                }
            } catch {
                Write-Log "Error checking File and Printer Sharing status: $($_.Exception.Message)" -Level Error
            }

            # Disable File and Printer Sharing
            try {
                Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled False
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable File and Printer Sharing: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Network Drives
        if ($NetworkConfig.NetworkDrives) {
            Write-Log "Mapping Network Drives..." -Level Info
            Write-SystemMessage -title "Mapping Network Drives"
            
            foreach ($drive in $NetworkConfig.NetworkDrives.Drive) {
                # Validate drive letter format
                if (-not ($drive.Letter -match "^[A-Z]$")) {
                    Write-Log "Invalid drive letter format: $($drive.Letter). Must be a single letter A-Z." -Level Error
                    Write-SystemMessage -errorMsg -msg "Invalid drive letter format: $($drive.Letter)"
                    continue
                }

                # Validate network path format
                if (-not ($drive.Path -match "^\\\\[^\/\\:*?""<>|]+\\.*")) {
                    Write-Log "Invalid network path format: $($drive.Path). Must be UNC path (\\server\share)." -Level Error
                    Write-SystemMessage -errorMsg -msg "Invalid network path format: $($drive.Path)"
                    continue
                }

                Write-SystemMessage -msg "Mapping network drive $($drive.Letter) to" -value $drive.Path
                Write-Log "Mapping network drive $($drive.Letter) to $($drive.Path)" -Level Info
                
                try {
                    # Remove existing drive mapping if it exists
                    if (Test-Path "$($drive.Letter):") {
                        Write-Log "Removing existing drive mapping for $($drive.Letter):" -Level Info
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
                        Write-SystemMessage -successMsg
                        Write-Log "Network drive $($drive.Letter): mapped successfully" -Level Info
                    } else {
                        Write-Log "Network path not accessible or does not exist: $($drive.Path)" -Level Error
                        Write-SystemMessage -errorMsg
                    }
                } catch {
                    Write-Log "Failed to map drive $($drive.Letter): $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg -msg "Failed to map network drive $($drive.Letter)"
                }
            }
        }

        Write-Log "Network configuration completed successfully" -Level Info
        return $true
    }
    catch {
        Write-Log "Error configuring network settings: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to configure network settings"
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
        Write-SystemMessage -title "Performing File Operations"

        # Copy Operations
        if ($FileConfig.Copy) {
            foreach ($file in $FileConfig.Copy.File) {
                # Validate source and destination paths
                if (-not $file.Source -or -not $file.Destination) {
                    Write-Log "Invalid file operation: Source or Destination missing" -Level Error
                    Write-SystemMessage -errorMsg -msg "Invalid file operation: Source or Destination missing"
                    continue
                }

                # Validate file paths for invalid characters
                $invalidChars = [IO.Path]::GetInvalidPathChars()
                if (($file.Source.IndexOfAny($invalidChars) -ge 0) -or ($file.Destination.IndexOfAny($invalidChars) -ge 0)) {
                    Write-Log "Invalid characters in path: Source=$($file.Source), Destination=$($file.Destination)" -Level Error
                    Write-SystemMessage -errorMsg -msg "Invalid characters in file path"
                    continue
                }

                Write-SystemMessage -msg "Copying file from" -value $file.Source
                Write-Log "Copying file from $($file.Source) to $($file.Destination)" -Level Info
                
                try {
                    # Create destination directory if it doesn't exist
                    $destinationDir = Split-Path -Parent $file.Destination
                    if (-not (Test-Path $destinationDir)) {
                        New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
                        Write-Log "Created destination directory: $destinationDir" -Level Info
                    }

                    # Copy file
                    if (Test-Path $file.Source) {
                        # Check if destination file exists
                        if (Test-Path $file.Destination) {
                            Write-Log "Destination file already exists, overwriting: $($file.Destination)" -Level Warning
                        }
                        Copy-Item -Path $file.Source -Destination $file.Destination -Force
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "Source file not found: $($file.Source)" -Level Warning
                        Write-SystemMessage -errorMsg -msg "Source file not found"
                    }
                } catch {
                    Write-Log "Failed to copy file: $($_.Exception.Message)" -Level Warning
                    Write-SystemMessage -errorMsg
                }
            }
        }

        # Delete Operations
        if ($FileConfig.Delete) {
            foreach ($file in $FileConfig.Delete.File) {
                # Validate file path
                if (-not $file) {
                    Write-Log "Invalid file operation: File path is empty" -Level Error
                    Write-SystemMessage -errorMsg -msg "Invalid file operation: File path is empty"
                    continue
                }

                # Validate file path for invalid characters
                $invalidChars = [IO.Path]::GetInvalidPathChars()
                if ($file.IndexOfAny($invalidChars) -ge 0) {
                    Write-Log "Invalid characters in path: $file" -Level Error
                    Write-SystemMessage -errorMsg -msg "Invalid characters in file path"
                    continue
                }

                Write-SystemMessage -msg "Deleting file" -value $file
                Write-Log "Deleting file: $file" -Level Info
                
                try {
                    if (Test-Path $file) {
                        # Check if file is read-only or system file
                        $fileInfo = Get-Item $file
                        if ($fileInfo.Attributes -match "ReadOnly|System") {
                            Write-Log "Warning: Attempting to delete protected file: $file" -Level Warning
                            Write-SystemMessage -warningMsg -msg "Attempting to delete protected file"
                        }

                        Remove-Item -Path $file -Force
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "File not found for deletion: $file" -Level Warning
                        Write-SystemMessage -errorMsg -msg "File not found"
                    }
                } catch {
                    $errorMsg = "Failed to delete file: $($_.Exception.Message)"
                    if ($_.Exception.Message -match "Access.*denied") {
                        $errorMsg += " (Access Denied)"
                    }
                    Write-Log $errorMsg -Level Warning
                    Write-SystemMessage -errorMsg
                }
            }
        }

        Write-Log "File operations completed successfully" -Level Info
        return $true
    }
    catch {
        Write-Log "Error performing file operations: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to perform file operations"
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
        Write-SystemMessage -title "Creating Shortcuts"

        foreach ($shortcut in $ShortcutConfig.Shortcut) {
            # Validate required properties
            if (-not $shortcut.Name -or -not $shortcut.Target) {
                Write-Log "Invalid shortcut configuration: Name or Target missing" -Level Error
                Write-SystemMessage -errorMsg -msg "Invalid shortcut configuration: Name or Target missing"
                continue
            }

            Write-SystemMessage -msg "Creating shortcut" -value $shortcut.Name
            Write-Log "Creating shortcut: $($shortcut.Name) -> $($shortcut.Target)" -Level Info

            # Validate target path exists
            if (-not (Test-Path $shortcut.Target)) {
                Write-Log "Target path does not exist: $($shortcut.Target)" -Level Error
                Write-SystemMessage -errorMsg -msg "Target path does not exist"
                continue
            }


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
                    Write-SystemMessage -errorMsg -msg "Shortcut location does not exist"
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
                        Write-SystemMessage -errorMsg -msg "Working directory does not exist"
                        continue
                    }
                    Write-Log "Setting working directory: $($shortcut.WorkingDirectory)"
                    $Shortcut.WorkingDirectory = $shortcut.WorkingDirectory
                }
                
                if ($shortcut.IconLocation) {
                    # Validate icon file exists
                    $iconPath = ($shortcut.IconLocation -split ',')[0]
                    if (-not (Test-Path $iconPath)) {
                        Write-Log "Icon file does not exist: $iconPath" -Level Warning
                        Write-SystemMessage -errorMsg -msg "Icon file does not exist"
                        continue
                    }
                    Write-Log "Setting icon location: $($shortcut.IconLocation)"
                    $Shortcut.IconLocation = $shortcut.IconLocation
                }

                # Save shortcut
                $Shortcut.Save()
                Write-SystemMessage -successMsg

            } catch {
                Write-Log "Failed to create shortcut $($shortcut.Name): $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg -msg "Failed to create shortcut"
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
        Write-SystemMessage -errorMsg -msg "Failed to create shortcuts. Check the logs for details."
        return $false
    }
}


# Main Execution Block
try {

    Clear-Host
    Show-SplashScreen -version $winforgeVersion

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

    # Windows Activation
    if ($configXML.Activation) {
        $configStatus['Activation'] = Set-WindowsActivation -ActivationConfig $configXML.Activation
    }

    # Environment Variables
    if ($configXML.EnvironmentVariables) {
        $configStatus['Environment'] = Set-EnvironmentVariables -EnvConfig $configXML.EnvironmentVariables
    }

    # Taskbar Configuration
    if ($configXML.Taskbar) {
        $configStatus['Taskbar'] = Set-TaskbarConfiguration -TaskbarConfig $configXML.Taskbar
    }

    # Theme Configuration
    if ($configXML.Theme) {
        $configStatus['Theme'] = Set-ThemeConfiguration -ThemeConfig $configXML.Theme
    }

    # System Tweaks
    if ($configXML.Tweaks) {
        $configStatus['Tweaks'] = Set-TweaksConfiguration -TweaksConfig $configXML.Tweaks
    }

    # Power
    if ($configXML.Power) {
        $configStatus['Power'] = Set-PowerConfiguration -PowerConfig $configXML.Power
    }

    # Network Configuration
    if ($configXML.Network) {
        $configStatus['Network'] = Set-NetworkConfiguration -NetworkConfig $configXML.Network
    }

    # Privacy
    if ($configXML.Privacy) {
        $configStatus['Privacy'] = Set-PrivacyConfiguration -PrivacyConfig $configXML.Privacy
    }

    # Security
    if ($configXML.Security) {
        $configStatus['Security'] = Set-SecurityConfiguration -SecurityConfig $configXML.Security
    }

    # Windows Update
    if ($configXML.WindowsUpdate) {
        $configStatus['WindowsUpdate'] = Set-WindowsUpdateConfiguration -UpdateConfig $configXML.WindowsUpdate
    }

    # Windows Features
    if ($configXML.WindowsFeatures) {
        $configStatus['WindowsFeatures'] = Set-WindowsFeaturesConfiguration -FeaturesConfig $configXML.WindowsFeatures
    }

    # Fonts installation
    if ($configXML.Fonts) {
        $configStatus['Fonts'] = Install-Fonts -FontConfig $configXML.Fonts
    }

    # Application Installation
    if ($configXML.Applications) {
        if ($configXML.Applications.Install) {
            $configStatus['ApplicationInstall'] = Install-Applications -AppConfig $configXML.Applications.Install
        }

        if ($configXML.Applications.Uninstall) {
            $configStatus['ApplicationUninstall'] = Remove-Applications -AppConfig $configXML.Applications.Uninstall
        }
    }

    # Google Configuration
    if ($configXML.Google) {
        $configStatus['Google'] = Set-GoogleConfiguration -GoogleConfig $configXML.Google
    }

    # Office Configuration
    if ($configXML.Office) {
        $configStatus['Office'] = Set-OfficeConfiguration -OfficeConfig $configXML.Office
    }


    # Registry modifications
    if ($configXML.Registry) {
        $configStatus['Registry'] = Set-RegistryEntries -RegistryConfig $configXML.Registry
    }

    # Scheduled Tasks
    if ($configXML.Tasks) {
        $configStatus['Tasks'] = Set-ScheduledTasksConfiguration -TasksConfig $configXML.Tasks
    }

    # File Operations
    if ($configXML.Files) {
        $configStatus['Files'] = Set-FileOperations -FileConfig $configXML.Files
    }

    # Shortcuts
    if ($configXML.Shortcuts) {
        $configStatus['Shortcuts'] = Set-Shortcuts -ShortcutConfig $configXML.Shortcuts
    }

    Write-SystemMessage -title "Configuration Completed"


    # Display configuration status
    Write-SystemMessage -title "Configuration Status"
    foreach ($item in $configStatus.GetEnumerator()) {
        $status = if ($item.Value) { "Success" } else { "Failed" }
        $color = if ($item.Value) { "Green" } else { "Red" }
        Write-Host "$($item.Key): " -NoNewline
        Write-Host $status -ForegroundColor $color
    }


    # Check if any configurations failed
    if ($configStatus.Values -contains $false) {
        Write-SystemMessage -msg "Some configurations failed. Please check the logs for details."
        Pause
        return 1
    }
    else {
        Write-SystemMessage -msg "All configurations completed successfully"
        if ($script:restartRequired) {
            Write-SystemMessage -title "Restart Required" -msg "Some changes require a system restart to take effect."
            $restart = Read-Host "Would you like to restart now? (Y/N)"
            switch ($restart) {
                'Y' {
                    Write-SystemMessage -msg "Restarting system..."
                    Restart-Computer -Force
                    return 0
                }
                'N' {
                    Write-SystemMessage -msg "System restart will be performed later."
                }
                default {
                    Write-SystemMessage -msg "Invalid input." -value "Select Y or N."
                }
            }
        }
    }

    Write-SystemMessage -title "Cleanup Temporary Files"

    $cleanup = Read-Host "Would you like to cleanup temporary files? (Y/N)"
    switch ($cleanup) {
        'Y' {
            Write-SystemMessage -msg "Cleaning up temporary files..."
            Write-Log "Cleaning up temporary files..."
            Remove-TempFiles
            Write-SystemMessage -successMsg
            Write-Log "Temporary files cleaned up successfully"
        }
        'N' {
            Write-SystemMessage -msg "Temporary files will not be removed."
            Write-Log "Temporary files will not be removed."
        }
        default {
            Write-SystemMessage -errorMsg -msg "Invalid input." -value "Select Y or N."
        }
    }


    Write-SystemMessage -msg "Winforge will now exit."
    Pause
}
catch {
    Write-Log "$($_.Exception.Message)" -Level Error
    Write-SystemMessage -errorMsg -msg "$($_.Exception.Message)"
    Pause
    return
}