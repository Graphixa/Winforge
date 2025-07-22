<#
.SYNOPSIS
    Windows configuration deployment tool using TOML configurations.
.DESCRIPTION
    Winforge automates Windows system configuration using TOML-based configuration files.
    Supports local and remote configurations with validation.

.PARAMETER ConfigPath
    Path to the configuration file (local .toml file or URL)
.PARAMETER LogPath
    Optional custom path for log file

.EXAMPLE
    .\winforge.ps1 -ConfigPath "myconfig.toml"

.EXAMPLE
    .\winforge.ps1 -ConfigPath "https://example.com/myconfig.toml" -LogPath "C:\Logs\winforge.log"

.NOTES

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
$script:configData = $null
$script:restartRequired = $false
$script:tempFiles = @()
$winforgeVersion = '0.2.0'

# Initialize Error Handling
$ErrorActionPreference = "Stop"

# Disable progress bar (Improves speed of)
$ProgressPreference = 'SilentlyContinue'



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

function Test-RequiredModules {
    # Check for required modules and return list of missing ones
    Write-SystemMessage -title "Checking Dependencies"

    $RequiredModules = @('PSToml')
    $MissingModules = @()

    foreach ($module in $RequiredModules) {
        Write-SystemMessage -msg "Checking for module" -value $module
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $MissingModules += $module
        }
    }

    if ($MissingModules.Count -gt 0) {
        return Install-RequiredModules -ModulesToInstall $MissingModules
    }
    
    # Import modules if they exist but aren't loaded
    foreach ($module in $RequiredModules) {
        if (-not (Get-Module -Name $module)) {
            try {
                Import-Module $module -ErrorAction Stop
                Write-Log "Successfully imported $module module" -Level Info
            }
            catch {
                Write-Log "Failed to import $module module: $($_.Exception.Message)" -Level Error
                return $false
            }
        }
    }
    
    Write-SystemMessage -msg "All required modules are available" -successMsg
    return $true
}

function Install-RequiredModules {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ModulesToInstall
    )

    Write-Log "Required modules are not available. Attempting to install them now." -Level Info

    $moduleList = $ModulesToInstall -join ", "
    Write-SystemMessage -msg "The following modules from PSGallery need to be installed to run Winforge" -value $moduleList -msgColor Yellow
    
    # Show GitHub link for PSToml
    if ($ModulesToInstall -contains 'PSToml') {
        Write-Host "`nMore information about PSToml: https://github.com/jborean93/PSToml" -ForegroundColor Cyan
    }
    
    Write-Host "`nWould you like to install them now? (Y/N)" -ForegroundColor Yellow
    $response = Read-Host
    
    switch -regex ($response.Trim()) {
        '^[Yy]$' {
            $success = $true
            foreach ($module in $ModulesToInstall) {
                try {
                    Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
                    Import-Module $module -ErrorAction Stop
                    Write-Log "$module module installed and imported successfully." -Level Info
                    Write-SystemMessage -msg "Module installed successfully" -value $module -successMsg
                }
                catch {
                    Write-Log "Failed to install/import $module module: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -msg "Failed to install module" -value "$module - $($_.Exception.Message)" -errorMsg
                    $success = $false
                }
            }
            return $success
        }
        '^[Nn]$' {
            Write-SystemMessage -msg "Required modules must be installed to continue" -errorMsg
            Write-Log "User declined to install required modules. Exiting.." -Level Error
            exit 1
        }
        default {
            Write-SystemMessage -msg "Invalid response. Please enter Y or N" -warningMsg
            return Install-RequiredModules -ModulesToInstall $ModulesToInstall # Recurse on invalid input
        }
    }
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

function Test-EncryptedConfig {
    <#
    .SYNOPSIS
        Tests if a configuration file is encrypted.
    .DESCRIPTION
        Determines if a configuration file is encrypted by checking for the presence
        of required encryption fields in the JSON wrapper.
    .PARAMETER FilePath
        The path to the configuration file to test (.toml or .config).
    .OUTPUTS
        Boolean. Returns $true if the file is encrypted, $false otherwise.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        # First check if file exists
        if (-not (Test-Path $FilePath)) {
            Write-Log "File not found: $FilePath" -Level Error
            return $false
        }

        # Validate file extension
        if (-not ($FilePath -match '\.(toml|config)$')) {
            Write-Log "Invalid file extension. Only .toml and .config files are supported." -Level Error
            return $false
        }

        # Read file content
        $content = Get-Content $FilePath -Raw -ErrorAction Stop

        # Try to parse as JSON to check for encryption wrapper
        try {
            $package = $content | ConvertFrom-Json
            # Check for required encryption fields
            return ($null -ne $package.Salt -and 
                   $null -ne $package.Data -and 
                   $null -ne $package.IV)
        }
        catch {
            # If we can't parse as JSON, it's not encrypted
                return $false
        }
    }
    catch {
        Write-Log "Error testing encrypted config: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Encrypts or decrypts a configuration file.
function Convert-SecureConfig {
    <#
    .SYNOPSIS
        Encrypts or decrypts a configuration file.
    .DESCRIPTION
        Handles the encryption and decryption of configuration files (.toml or .config).
        Uses AES-256 encryption with PBKDF2 key derivation.
    .PARAMETER FilePath
        The path to the configuration file to encrypt/decrypt.
    .PARAMETER IsEncrypting
        Boolean indicating whether to encrypt ($true) or decrypt ($false).
    .PARAMETER Password
        The password to use for encryption/decryption.
    .OUTPUTS
        Boolean. Returns $true on success, $false on failure.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [bool]$IsEncrypting,
        
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$Password
    )

    try {
        # Convert SecureString to plain text only when needed
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    try {
        # Verify file exists
        if (-not (Test-Path $FilePath)) {
            throw "File not found: $FilePath"
        }

            # Validate file extension
            if (-not ($FilePath -match '\.(toml|config)$')) {
                throw "Invalid file extension. Only .toml and .config files are supported."
            }

        # Get file content
        $configContent = Get-Content $FilePath -Raw

            # Generate output path (keep original extension)
        $outputPath = $FilePath

        if ($IsEncrypting) {
            # Check if already encrypted
            if (Test-EncryptedConfig -FilePath $FilePath) {
                throw "File is already encrypted. Decrypt it first if you want to re-encrypt."
            }

            # Generate unique random salt
            $salt = New-Object byte[] 32
                $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
            try {
                $rng.GetBytes($salt)
            }
            finally {
                $rng.Dispose()
            }

                # Create key and IV using PBKDF2
                $rfc = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($plainPassword, $salt, 1000)
            try {
                $key = $rfc.GetBytes(32) # 256 bits
                    $iv = $rfc.GetBytes(16)  # 128 bits

                # Convert content to bytes
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($configContent)

                # Create AES encryption object
                $aes = [System.Security.Cryptography.Aes]::Create()
                try {
                        $aes.Key = $key
                        $aes.IV = $iv
                        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

                    # Create encryptor and encrypt
                    $encryptor = $aes.CreateEncryptor()
                    try {
                        $encrypted = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
                    }
                    finally {
                        $encryptor.Dispose()
                    }
                    
                        # Create final encrypted package
                    $package = @{
                        Salt = [Convert]::ToBase64String($salt)
                        Data = [Convert]::ToBase64String($encrypted)
                            IV = [Convert]::ToBase64String($iv)
                    } | ConvertTo-Json
                    
                    # Save encrypted content
                    $package | Set-Content $outputPath
                        Write-Host "File encrypted successfully: $outputPath"
                        Write-Log "File encrypted successfully: $outputPath"
                    
                        return $true
                }
                finally {
                    $aes.Dispose()
                    # Securely clear sensitive data from memory
                    for ($i = 0; $i -lt $key.Length; $i++) { $key[$i] = 0 }
                        for ($i = 0; $i -lt $iv.Length; $i++) { $iv[$i] = 0 }
                }
            }
            finally {
                $rfc.Dispose()
            }
        }
        else {
            try {
                    Write-Log "Attempting to decrypt file"
                
                # Parse the encrypted package
                    $package = Get-Content $FilePath -Raw | ConvertFrom-Json
                    $salt = [Convert]::FromBase64String($package.Salt)
                $encrypted = [Convert]::FromBase64String($package.Data)
                    $iv = [Convert]::FromBase64String($package.IV)

                # Recreate key from password and stored salt
                    $rfc = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($plainPassword, $salt, 1000)
                try {
                    $key = $rfc.GetBytes(32)

                    # Create AES decryption object
                    $aes = [System.Security.Cryptography.Aes]::Create()
                    try {
                            $aes.Key = $key
                            $aes.IV = $iv
                            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

                        # Create decryptor and decrypt
                        $decryptor = $aes.CreateDecryptor()
                        try {
                            $decrypted = $decryptor.TransformFinalBlock($encrypted, 0, $encrypted.Length)
                                $decryptedContent = [System.Text.Encoding]::UTF8.GetString($decrypted)
                                
                                # Save decrypted content
                                $decryptedContent | Set-Content $outputPath -NoNewline
                                Write-SystemMessage -msg "File decrypted successfully" -value $outputPath -successMsg
                                Write-Log "File decrypted successfully: $outputPath"
                                
                                return $true
                        }
                        catch {
                                throw "Failed to decrypt file. Please check the password and try again."
                        }
                        finally {
                            $decryptor.Dispose()
                        }
                    }
                    finally {
                        $aes.Dispose()
                            # Securely clear key from memory
                        for ($i = 0; $i -lt $key.Length; $i++) { $key[$i] = 0 }
                    }
                }
                finally {
                    $rfc.Dispose()
                }
            }
            catch {
                    Write-Host "Decryption failed: $($_.Exception.Message)"
                    Write-Log "Decryption failed: $($_.Exception.Message)" -Level Error
                    return $false
                }
            }
        }
        finally {
            # Clear the plain text password from memory
            if ($plainPassword) {
                $plainPassword = "0" * $plainPassword.Length
                Remove-Variable plainPassword
            }
            if ($BSTR) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            }
        }
    }
    catch {
        Write-Host "Operation failed: $($_.Exception.Message)"
        Write-Log "Operation failed: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Converts a Google Drive link to a direct download link.
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

# Downloads the configuration file from the given path.
function Get-ConfigFile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    Write-Log "Downloading configuration from: $Path"
    Write-SystemMessage -msg "Downloading configuration from" -value $Path
    $extension = if ($Path -match '\.toml$') { '.toml' } else { '.config' }
    $tempPath = Join-Path $env:TEMP "winforge$extension"
    $script:tempFiles += $tempPath
   
    try {
        Invoke-WebRequest -Uri $Path -OutFile $tempPath -UseBasicParsing -ErrorAction Stop
        Write-SystemMessage -successMsg -msg "Configuration downloaded successfully" -value $tempPath
        return $tempPath
    }
    catch {
        Write-Log "Failed to download configuration from ${Path}: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to download configuration"
        Pause
        exit 1
    }
}

# Function to handle decryption of encrypted configuration files
function Decrypt-Config {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$Password
    )
    
    try {
        # Convert SecureString to plain text temporarily for decryption
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $passwordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        
        # Check for empty password
        if ([string]::IsNullOrWhiteSpace($passwordText)) {
            throw "Password cannot be empty"
        }
        
        try {
            $decryptResult = Convert-SecureConfig -FilePath $FilePath -IsEncrypting $false -Password $Password
            if ($decryptResult) {
                Write-SystemMessage -successMsg "Configuration decrypted successfully"
                
                # Parse decrypted TOML content
                $config = Get-Content -Path $FilePath -Raw -ErrorAction Stop | ConvertFrom-Toml
                return $config
            }
            else {
                throw "Decryption failed - incorrect password"
            }
        }
        catch {
            Write-Log "Decryption error: $($_.Exception.Message)" -Level Error
            throw
        }
    }
    finally {
        # Clean up sensitive data
        if ($bstr) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        Remove-Variable -Name passwordText -ErrorAction SilentlyContinue
    }
}

# Restore original decryption code in Read-ConfigFile
function Read-ConfigFile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Path -match '^https?://') {
        # Check if URL is a Google Drive link
        if ($Path -match "drive\.google\.com") {
            $Path = Convert-GoogleDriveLink -Url $Path
        }
        $Path = Get-ConfigFile -Path $Path
    }

    try {
        Write-SystemMessage -title "Winforge Configuration" 
        Write-SystemMessage -msg "Loading configuration file"
        
        # Check if file exists
        if (-not (Test-Path $Path)) {
            Write-SystemMessage -errorMsg -msg "Configuration file not found"
            throw "Configuration file not found: $Path"
        }
        
        # Validate file extension
        $extension = [System.IO.Path]::GetExtension($Path)
        if ($extension -notin @('.toml', '.config')) {
            Write-SystemMessage -errorMsg -msg "Invalid file format"
            throw "Configuration must have the extension .toml or .config and be in TOML format"
        }
        
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
                    $decryptResult = Convert-SecureConfig -FilePath $Path -IsEncrypting $false -Password $password
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

        try {
            $config = Get-Content -Path $Path -Raw -ErrorAction Stop | ConvertFrom-Toml
            return $config
        }
        catch {
            throw "Invalid TOML in configuration file: $($_.Exception.Message)"
        }
    }
    catch {
        Write-Log "Failed to load configuration: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to load configuration" -value "$($_.Exception.Message)"
        
        if ($_.Exception.Message -match "Maximum password attempts reached" -or 
            $_.Exception.Message -match "Failed to decrypt configuration after") {
            throw
        }
        else {
            return $null
        }
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

    switch -regex ($Path) {
        '^HKLM:\\|^HKEY_LOCAL_MACHINE\\' {
            $baseKey = "HKLM:"
            $pathWithoutHive = $Path -replace '^HKLM:\\|^HKEY_LOCAL_MACHINE\\', ''
        }
        '^HKCU:\\|^HKEY_CURRENT_USER\\' {
            $baseKey = "HKCU:"
            $pathWithoutHive = $Path -replace '^HKCU:\\|^HKEY_CURRENT_USER\\', ''
        }
        '^HKCR:\\|^HKEY_CLASSES_ROOT\\' {
            $baseKey = "HKCR:"
            $pathWithoutHive = $Path -replace '^HKCR:\\|^HKEY_CLASSES_ROOT\\', ''
        }
        '^HKU:\\|^HKEY_USERS\\' {
            $baseKey = "HKU:"
            $pathWithoutHive = $Path -replace '^HKU:\\|^HKEY_USERS\\', ''
        }
        '^HKCC:\\|^HKEY_CURRENT_CONFIG\\' {
            $baseKey = "HKCC:"
            $pathWithoutHive = $Path -replace '^HKCC:\\|^HKEY_CURRENT_CONFIG\\', ''
        }
        default {
            Write-Log "Unsupported registry hive in path: $Path" -Level Error
            return $false
        }
    }
    
    # Construct proper registry path
    $registryPath = Join-Path $baseKey $pathWithoutHive
    
    try {
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            Write-Log "Created new registry key: $registryPath" -Level Info
        }
        
        if ($Action -eq 'add') {
            Set-ItemProperty -Path $registryPath -Name $Name -Value $Value -Type $Type -Force | Out-Null
            Write-Log "Added/Updated registry value: $Name in $registryPath" -Level Info
        }
        elseif ($Action -eq 'remove') {
            Remove-ItemProperty -Path $registryPath -Name $Name -Force -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Removed registry value: $Name from $registryPath" -Level Info
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

    $isProgramInstalled = $InstalledSoftware | Where-Object { $_.DisplayName -like "*$ProgramName*" }

    return $isProgramInstalled
}

function Set-SystemCheckpoint {

    Write-SystemMessage -title "Creating System Restore Point"
    Write-Log "Creating system restore point" -Level Info

    try {
        # Check if System Restore is enabled
        $srEnabled = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if (-not $srEnabled) {
            Write-Log "System Restore is not enabled. Attempting to enable" -Level Warning
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
        
       
        Checkpoint-Computer -Description $snapshotName -RestorePointType "MODIFY_SETTINGS" -WarningAction SilentlyContinue | Out-Null
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
    <#
    .SYNOPSIS
        Configures system settings based on the configuration file.
    .DESCRIPTION
        TODO: Update for TOML Support
        - Convert boolean handling from strings to native TOML booleans
        - Update naming conventions (Disable/Allow prefixes)
        - Add support for new settings (WindowsRecall, SetupDevicePrompt)
        - Convert EnableRemoteDesktop to DisableRemoteDesktop
    #>
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$SystemConfig
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
        if ($SystemConfig.DisableRemoteDesktop -eq $true) {
            Write-Log "Disabling Remote Desktop" -Level Info
            Write-SystemMessage -msg "Disabling Remote Desktop"
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
        elseif ($SystemConfig.DisableRemoteDesktop -eq $false) {
            Write-Log "Enabling Remote Desktop" -Level Info
            Write-SystemMessage -msg "Enabling Remote Desktop"
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

        # Windows Recall
        if ($SystemConfig.DisableWindowsRecall -eq $true) {
            Write-Log "Disabling Windows Recall" -Level Info
            Write-SystemMessage -msg "Disabling Windows Recall"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsRecall" -Name "DisableWindowsRecall" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to disable Windows Recall: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($SystemConfig.DisableWindowsRecall -eq $false) {
            Write-Log "Enabling Windows Recall" -Level Info
            Write-SystemMessage -msg "Enabling Windows Recall"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsRecall" -Name "DisableWindowsRecall" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to enable Windows Recall: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Windows Store
        if ($SystemConfig.DisableWindowsStore -eq $true) {
            Write-Log "Disabling Windows Store" -Level Info
            Write-SystemMessage -msg "Disabling Windows Store"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to disable Windows Store: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($SystemConfig.DisableWindowsStore -eq $false) {
            Write-Log "Enabling Windows Store" -Level Info
            Write-SystemMessage -msg "Enabling Windows Store"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to enable Windows Store: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        if ($SystemConfig.DisableOneDrive -eq $true) {
            Write-Log "Disabling OneDrive" -Level Info
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
        elseif ($SystemConfig.DisableOneDrive -eq $false) {
            Write-Log "Enabling OneDrive" -Level Info
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

        if ($SystemConfig.DisableCopilot -eq $true) {
            Write-Log "Disabling Windows Copilot" -Level Info
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
        elseif ($SystemConfig.DisableCopilot -eq $false) {
            Write-Log "Enabling Windows Copilot" -Level Info
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
        if ($SystemConfig.ShowFileExtensions -eq $true) {
            Write-SystemMessage -msg "Showing file extensions"
            Write-Log "Showing file extensions" -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to show file extensions: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($SystemConfig.ShowFileExtensions -eq $false) {
            Write-SystemMessage -msg "Hiding file extensions"
            Write-Log "Hiding file extensions" -Level Info
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
        if ($SystemConfig.ShowHiddenFiles -eq $true) {
            Write-SystemMessage -msg "Showing hidden files"
            Write-Log "Showing hidden files" -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to show hidden files: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($SystemConfig.ShowHiddenFiles -eq $false) {
            Write-SystemMessage -msg "Hiding hidden files"
            Write-Log "Hiding hidden files" -Level Info
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
        if ($SystemConfig.DisableSetupDevicePrompt -eq $true) {
            Write-SystemMessage -msg "Disabling Setup Device Prompt"
            Write-Log "Disabling Setup Device Prompt" -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagemen" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to disable Setup Device Prompt: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($SystemConfig.DisableSetupDevicePrompt -eq $false) {
            Write-SystemMessage -msg "Enabling Setup Device Prompt"
            Write-Log "Enabling Setup Device Prompt" -Level Info
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
        Write-Log "Error configuring system settings: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to configure system settings"
        return $false
    }
}

function Set-SecurityConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$SecurityConfig
    )
    
    Write-SystemMessage -title "Configuring Security Settings"
    $success = $true

    try {
        # Microsoft Defender Configuration
        if ($SecurityConfig.MicrosoftDefender -eq "Enable") {
            Write-Log "Enabling Microsoft Defender" -Level Info
            Write-SystemMessage -msg "Enabling Microsoft Defender"
            try {
                Set-MpPreference -DisableRealtimeMonitoring $false
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to enable Microsoft Defender: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
                $success = $false
            }
        }
        elseif ($SecurityConfig.MicrosoftDefender -eq "Disable") {
            Write-Log "Disabling Microsoft Defender" -Level Info
            Write-SystemMessage -msg "Disabling Microsoft Defender"
            try {
                Set-MpPreference -DisableRealtimeMonitoring $true
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to disable Microsoft Defender: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
                $success = $false
            }
        }

        # UAC Configuration
        if ($SecurityConfig.UAC.Enable -eq $true) {
            Write-Log "Enabling UAC" -Level Info
            Write-SystemMessage -msg "Enabling UAC"
            try {
                # Enable UAC
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 1
                Write-SystemMessage -successMsg

                if ($SecurityConfig.UAC.Level) {
                    Write-SystemMessage -msg "Setting UAC level to" -value $($SecurityConfig.UAC.Level)

                    $uacValue = switch ($SecurityConfig.UAC.Level) {
                        "AlwaysNotify" { 3 }
                        "NotifyChanges" { 2 }
                        "NotifyNoDesktop" { 1 }
                        "NeverNotify" { 0 }
                        default { 
                            Write-Log "Invalid UAC level specified: $($SecurityConfig.UAC.Level). Using default (NotifyChanges)" -Level Warning
                            2  # Return the default value directly
                        }
                    }

                    try {
                        Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value $uacValue
                        Write-SystemMessage -successMsg
                    }
                    catch {
                        Write-Log "Failed to set UAC level: $($_.Exception.Message)" -Level Error
                        Write-SystemMessage -errorMsg
                    }
                }
                
            }
            catch {
                Write-Log "Failed to configure UAC: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
                $success = $false
            }
        }
        elseif ($SecurityConfig.UAC.Enable -eq $false) {
            Write-SystemMessage -msg "Disabling UAC"
            Write-Log "Disabling UAC" -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to disable UAC: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
                $success = $false
            }
        }

        # AutoPlay Configuration
        if ($SecurityConfig.DisableAutoPlay -eq $true) {
            Write-Log "Disabling AutoPlay" -Level Info
            Write-SystemMessage -msg "Disabling AutoPlay"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to disable AutoPlay: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
                $success = $false
            }
        }
        elseif ($SecurityConfig.DisableAutoPlay -eq $false) {
            Write-Log "Enabling AutoPlay" -Level Info
            Write-SystemMessage -msg "Enabling AutoPlay"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            }
            catch {
                Write-Log "Failed to enable AutoPlay: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
                $success = $false
            }
        }

        # BitLocker Configuration
        if ($SecurityConfig.Bitlocker) {
            Write-Log "Configuring BitLocker" -Level Info
            Write-SystemMessage -msg "Configuring BitLocker"

            foreach ($driveConfig in $SecurityConfig.Bitlocker) {
                $driveLetter = $driveConfig.Drive
                Write-Log "Processing BitLocker for drive $driveLetter" -Level Info
                Write-SystemMessage -msg "Processing BitLocker" -value $driveLetter

                try {
                    # Check if drive exists
                    if (-not (Test-Path -Path $driveLetter)) {
                        throw "Drive $driveLetter does not exist"
                    }

                    # Convert password to secure string
                    $securePassword = ConvertTo-SecureString $driveConfig.Password -AsPlainText -Force

                    # Create recovery key directory if it doesn't exist
                    $recoveryKeyDir = Split-Path $driveConfig.RecoveryKeyPath -Parent
                    if (-not (Test-Path -Path $recoveryKeyDir)) {
                        New-Item -Path $recoveryKeyDir -ItemType Directory -Force | Out-Null
                    }

                    # Check if BitLocker is already enabled
                    $bitlockerVolume = Get-BitLockerVolume -MountPoint $driveLetter
                    if ($bitlockerVolume.ProtectionStatus -eq "Off") {
                        # Enable BitLocker with specified settings
                        Enable-BitLocker -MountPoint $driveLetter `
                            -EncryptionMethod $driveConfig.EncryptionMethod `
                            -UsedSpaceOnly:($driveConfig.EncryptionType -eq "UsedSpace") `
                            -PasswordProtector -Password $securePassword `
                            -RecoveryKeyPath $driveConfig.RecoveryKeyPath `
                            -SkipHardwareTest

                        Write-SystemMessage -successMsg -msg "Enabled BitLocker on drive" -value $driveLetter
                    }
                    else {
                        Write-Log "BitLocker is already enabled on drive $driveLetter" -Level Info
                        Write-SystemMessage -msg "BitLocker already enabled on drive" -value $driveLetter
                    }
                }
                catch {
                    Write-Log "Failed to configure BitLocker for drive $driveLetter`: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                    $success = $false
                }
            }
        }

        Write-Log "Security configuration completed"
        return $success
    }
    catch {
        Write-Log "Error configuring security settings: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to configure security settings"
        return $false
    }
}

function Set-PrivacyConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$PrivacyConfig
    )
    
    Write-SystemMessage -title "Configuring Privacy Settings"

    try {
        # Telemetry
        if ($PrivacyConfig.DisableTelemetry -eq $true) {
            Write-SystemMessage -msg "Disabling telemetry"
            Write-Log "Disabling telemetry" -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable telemetry: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableTelemetry -eq $false) {
            Write-SystemMessage -msg "Enabling telemetry"
            Write-Log "Enabling telemetry" -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable telemetry: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # DiagTrack
        if ($PrivacyConfig.DisableDiagTrack -eq $true) {
            Write-SystemMessage -msg "Disabling diagnostic tracking"
            Write-Log "Disabling diagnostic tracking" -Level Info
            try {
                Stop-Service "DiagTrack" -Force | Out-Null
                Set-Service "DiagTrack" -StartupType Disabled | Out-Null
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable diagnostic tracking: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableDiagTrack -eq $false) {
            Write-SystemMessage -msg "Enabling diagnostic tracking"
            Write-Log "Enabling diagnostic tracking" -Level Info
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
        if ($PrivacyConfig.DisableAppPrivacy -eq $true) {
            Write-SystemMessage -msg "Configuring app privacy settings"
            Write-Log "Configuring app privacy settings"
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Type String -Value "Deny"
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Type String -Value "Deny"
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to configure app privacy settings: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableAppPrivacy -eq $false) {
            Write-SystemMessage -msg "Enabling app privacy settings"
            Write-Log "Enabling app privacy settings"
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
        if ($PrivacyConfig.DisableStartMenuTracking -eq $true) {
            Write-SystemMessage -msg "Disabling Start Menu tracking"
            Write-Log "Disabling Start Menu tracking" -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Start Menu tracking: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableStartMenuTracking -eq $false) {
            Write-SystemMessage -msg "Enabling Start Menu tracking"
            Write-Log "Enabling Start Menu tracking" -Level Info
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
        if ($PrivacyConfig.DisableActivityHistory -eq $true) {
            Write-SystemMessage -msg "Disabling Activity History"
            Write-Log "Disabling Activity History"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Activity History: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableActivityHistory -eq $false) {
            Write-SystemMessage -msg "Enabling Activity History"
            Write-Log "Enabling Activity History" -Level Info
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
        if ($PrivacyConfig.DisableClipboardDataCollection -eq $true) {
            Write-SystemMessage -msg "Disabling Clipboard data collection"
            Write-Log "Disabling Clipboard data collection" -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Clipboard data collection: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableClipboardDataCollection -eq $false) {
            Write-SystemMessage -msg "Enabling Clipboard data collection"
            Write-Log "Enabling Clipboard data collection" -Level Info
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
        if ($PrivacyConfig.DisableStartMenuSuggestions -eq $true) {
            Write-SystemMessage -msg "Disabling Start Menu suggestions"
            Write-Log "Disabling Start Menu suggestions" -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Start Menu suggestions: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PrivacyConfig.DisableStartMenuSuggestions -eq $false) {
            Write-SystemMessage -msg "Enabling Start Menu suggestions"
            Write-Log "Enabling Start Menu suggestions" -Level Info
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
        [PSCustomObject]$AppConfig,
        
        [Parameter(Mandatory = $false)]
        [string]$packageManager = "Winget"
    )

    Write-SystemMessage -title "Installing Applications"

    try {
        # Chocolatey Apps
        if ($packageManager -eq "Chocolatey") {
            # Ensure Chocolatey is installed
            if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
                Write-Log "Chocolatey is not installed. Installing" -Level Info
                Write-SystemMessage -msg "Installing Chocolatey"
                
                try {
                    $installScript = {
                        $ProgressPreference = 'SilentlyContinue'
                        Set-ExecutionPolicy Bypass -Scope Process -Force
                        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
                    }
                    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command & {$installScript}" -Wait -WindowStyle Hidden
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to install Chocolatey: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                    return $false
                }
            }

            # Refresh environment variables to ensure choco command is available
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            Write-Log "Refreshed environment variables to include Chocolatey" -Level Info

            # Install Chocolatey Apps
            foreach ($appItem in $AppConfig.Chocolatey) {
                if ([string]::IsNullOrWhiteSpace($appItem.Name)) {
                    Write-Log "Empty application name found. Skipping" -Level Warning
                    continue
                }

                Write-SystemMessage -msg "Installing" -value $appItem.Name
                Write-Log "Installing $($appItem.Name)" -Level Info
                
                try {
                    # Check if app is already installed
                    $installedApp = choco list --local-only --exact $appItem.Name | Where-Object { $_ -match "^$($appItem.Name)\s" }
                    if ($installedApp) {
                        Write-Log "$($appItem.Name) is already installed" -Level Warning
                        Write-SystemMessage -warningMsg -msg "App is already installed"
                        continue
                    }

                    $chocoArgs = if ($appItem.Version) {
                        "install `"$($appItem.Name)`" --version $($appItem.Version) -y -r --ignoredetectedreboot"
                    } else {
                        "install `"$($appItem.Name)`" -y -r --ignoredetectedreboot" 
                    }
                    
                    $result = Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command & { choco $chocoArgs }" -Wait -WindowStyle Hidden -PassThru
                    
                    if ($result.ExitCode -eq 0) {
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "Failed to install $($appItem.Name). Exit code: $($result.ExitCode)" -Level Error
                        Write-SystemMessage -errorMsg
                    }
                }
                catch {
                    Write-Log "Failed to install $($appItem.Name) : $($_.Exception.Message)" -Level Error
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
            foreach ($appItem in $AppConfig.Winget) {
                if ([string]::IsNullOrWhiteSpace($appItem.Name)) {
                    Write-Log "Empty application name found. Skipping" -Level Warning
                    continue
                }

                Write-SystemMessage -msg "Installing" -value $appItem.Name
                Write-Log "Installing $($appItem.Name)" -Level Info
                
                try {
                    # Search for exact package first
                    $searchResult = winget search --exact --query $appItem.Name --accept-source-agreements | Out-String
                    if ($searchResult -notmatch $appItem.Name) {
                        Write-Log "Package $($appItem.Name) not found in winget repository" -Level Warning
                        Write-SystemMessage -warningMsg -msg "Package not found in repository"
                        continue
                    }

                    if ($appItem.Version) {
                        $result = Start-Process -FilePath "winget" -ArgumentList "install --exact --id $($appItem.Name) --version $($appItem.Version) --accept-source-agreements --accept-package-agreements" -Wait -NoNewWindow -PassThru
                    }
                    else {
                        $result = Start-Process -FilePath "winget" -ArgumentList "install --exact --id $($appItem.Name) --accept-source-agreements --accept-package-agreements" -Wait -NoNewWindow -PassThru
                    }
                    
                    if ($result.ExitCode -eq 0) {
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "Failed to install $($appItem.Name). Exit code: $($result.ExitCode)" -Level Error
                        Write-SystemMessage -errorMsg
                    }
                }
                catch {
                    Write-Log "Failed to install $($appItem.Name) : $($_.Exception.Message)" -Level Error
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
        [PSCustomObject]$AppConfig
    )

    Write-SystemMessage -title "Removing Applications"

    try {
        # Debug logging
        Write-Log "Debug: AppConfig type: $($AppConfig.GetType().FullName)" -Level Info
        Write-Log "Debug: AppConfig content: $($AppConfig | Format-List | Out-String)" -Level Info
        Write-Log "Debug: PackageManager value: $($AppConfig.PackageManager)" -Level Info
        Write-Log "Debug: Number of apps: $($AppConfig.App.Count)" -Level Info

        if (-not $AppConfig) {
            Write-Log "No applications to uninstall" -Level Info
            return $true
        }

        $packageManager = $AppConfig.Attributes["PackageManager"].Value
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

            foreach ($app in $AppConfig.ChildNodes) {
                if ($app.Name -ne "App") { continue }
                $appName = $app.InnerText.Trim()

                if ([string]::IsNullOrWhiteSpace($appName)) {
                    Write-Log "Empty application name found. Skipping" -Level Warning
                    continue
                }

                Write-SystemMessage -msg "Uninstalling" -value $appName
                Write-Log "Uninstalling $appName" -Level Info
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
                        Write-SystemMessage -warningMsg -msg "Not installed on this system"
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

            # Refresh environment variables to ensure choco command is available
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            Write-Log "Refreshed environment variables to include Chocolatey" -Level Info

            foreach ($app in $AppConfig.ChildNodes) {
                if ($app.Name -ne "App") { continue }
                $appName = $app.InnerText.Trim()

                if ([string]::IsNullOrWhiteSpace($appName)) {
                    Write-Log "Empty application name found. Skipping" -Level Warning
                    continue
                }

                Write-SystemMessage -msg "Uninstalling" -value $appName
                Write-Log "Uninstalling $appName" -Level Info
                try {
                    # Check if app is installed first
                    $listResult = Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command & { choco list $appName -e }" -Wait -WindowStyle Hidden -PassThru
                    if ($listResult.ExitCode -eq 0) {
                        $result = Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command & { choco uninstall `"$appName`" -y -r --ignoredetectedreboot}" -Wait -WindowStyle Hidden -PassThru
                        if ($result.ExitCode -eq 0) {
                            Write-SystemMessage -successMsg
                        } else {
                            Write-Log "Failed to uninstall $appName. Exit code: $($result.ExitCode)" -Level Error
                            Write-SystemMessage -errorMsg
                        }
                    }
                    else {
                        Write-Log "App $appName is not installed" -Level Info
                        Write-SystemMessage -warningMsg -msg "Not installed on this system"
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
        Write-Log "Error removing applications: $($_.Exception.Message)" -Level Error
        Write-Log "Error removing applications: $($_.ScriptStackTrace)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to remove applications. Check the log for details."
        return $false
    }
}

function Set-EnvironmentVariables {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$EnvConfig
    )
    
    Write-SystemMessage -title "Setting Environment Variables"

    try {
        # Process System variables
        if ($EnvConfig.System) {
            Write-Log "Processing System environment variables" -Level Info
            foreach ($envItem in $EnvConfig.System) {
                if (-not $envItem.Name -or -not $envItem.Value) {
                    Write-Log "Invalid environment variable entry: Missing Name or Value" -Level Warning
                    continue
                }

                Write-Log "Setting system environment variable: $($envItem.Name) = $($envItem.Value)" -Level Info
                Write-SystemMessage -msg "Setting system environment variable" -value $envItem.Name

                try {
                    # Expand any environment variables in the value
                    $expandedValue = $ExecutionContext.InvokeCommand.ExpandString($envItem.Value)
                    [System.Environment]::SetEnvironmentVariable($envItem.Name, $expandedValue, [System.EnvironmentVariableTarget]::Machine)
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to set system environment variable: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
        }

        # Process User variables
        if ($EnvConfig.User) {
            Write-Log "Processing User environment variables" -Level Info
            foreach ($envItem in $EnvConfig.User) {
                if (-not $envItem.Name -or -not $envItem.Value) {
                    Write-Log "Invalid environment variable entry: Missing Name or Value" -Level Warning
                    continue
                }

                Write-Log "Setting user environment variable: $($envItem.Name) = $($envItem.Value)" -Level Info
                Write-SystemMessage -msg "Setting user environment variable" -value $envItem.Name

                try {
                    # Expand any environment variables in the value
                    $expandedValue = $ExecutionContext.InvokeCommand.ExpandString($envItem.Value)
                    [System.Environment]::SetEnvironmentVariable($envItem.Name, $expandedValue, [System.EnvironmentVariableTarget]::User)
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to set user environment variable: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
        }

        # Process Path additions (System)
        if ($EnvConfig.AddToPath.System) {
            Write-Log "Processing System PATH additions" -Level Info
            $currentPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
            
            foreach ($pathItem in $EnvConfig.AddToPath.System) {
                if (-not $pathItem) {
                    Write-Log "Empty PATH entry found, skipping" -Level Warning
                    continue
                }

                Write-Log "Adding to system PATH: $pathItem" -Level Info
                Write-SystemMessage -msg "Adding to system PATH" -value $pathItem

                try {
                    $expandedPath = $ExecutionContext.InvokeCommand.ExpandString($pathItem)
                    if ($currentPath -notlike "*$expandedPath*") {
                        $currentPath = "$currentPath;$expandedPath"
                        [System.Environment]::SetEnvironmentVariable("Path", $currentPath, [System.EnvironmentVariableTarget]::Machine)
                        Write-SystemMessage -successMsg
                    }
                    else {
                        Write-Log "Path already exists in system PATH: $expandedPath" -Level Warning
                        Write-SystemMessage -warningMsg -msg "Path already exists"
                    }
                }
                catch {
                    Write-Log "Failed to add to system PATH: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
        }

        # Process Path additions (User)
        if ($EnvConfig.AddToPath.User) {
            Write-Log "Processing User PATH additions" -Level Info
            $currentPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::User)
            
            foreach ($pathItem in $EnvConfig.AddToPath.User) {
                if (-not $pathItem) {
                    Write-Log "Empty PATH entry found, skipping" -Level Warning
                    continue
                }

                Write-Log "Adding to user PATH: $pathItem" -Level Info
                Write-SystemMessage -msg "Adding to user PATH" -value $pathItem

                try {
                    $expandedPath = $ExecutionContext.InvokeCommand.ExpandString($pathItem)
                    if ($currentPath -notlike "*$expandedPath*") {
                        $currentPath = "$currentPath;$expandedPath"
                        [System.Environment]::SetEnvironmentVariable("Path", $currentPath, [System.EnvironmentVariableTarget]::User)
                        Write-SystemMessage -successMsg
                    }
                    else {
                        Write-Log "Path already exists in user PATH: $expandedPath" -Level Warning
                        Write-SystemMessage -warningMsg -msg "Path already exists"
                    }
                }
                catch {
                    Write-Log "Failed to add to user PATH: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
        }

        Write-Log "Environment variables configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error setting environment variables: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to set environment variables. Check the log for details."
        return $false
    }
}

function Set-WindowsActivation {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ActivationConfig
    )
    
    Write-SystemMessage -title "Windows Activation"

    try {
        $productKey = $ActivationConfig.ProductKey
        $version = $ActivationConfig.Version
        
        # Install product key
        if ($productKey) {
            Write-SystemMessage -msg "Activating Windows with product key"
            Write-Log "Activating Windows with product key" -Level Info
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
        [PSCustomObject]$UpdateConfig
    )
    
    Write-SystemMessage -title "Configuring Windows Update"

    try {        
        # Auto Update Settings
        if ($UpdateConfig.AutomaticUpdates) {
            Write-SystemMessage -msg "Configuring automatic updates"
            Write-Log "Setting automatic updates to: $($UpdateConfig.AutomaticUpdates)"
            try {
                if ($UpdateConfig.AutomaticUpdates -eq $true) {
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutomaticUpdates" -Type DWord -Value 0
                } elseif ($UpdateConfig.AutomaticUpdates -eq $false) {
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
            Write-SystemMessage -msg "Setting update behavior"
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
            Write-SystemMessage -msg "Configuring update schedule"
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
        if ($UpdateConfig.AutoInstallMinorUpdates -eq $true) {
            Write-SystemMessage -msg "Enabling automatic minor updates"
            Write-Log "Enabling automatic minor updates"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutoInstallMinorUpdates" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable automatic minor updates: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($UpdateConfig.AutoInstallMinorUpdates -eq $false) {
            Write-SystemMessage -msg "Disabling automatic minor updates"
            Write-Log "Disabling automatic minor updates"
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
        [PSCustomObject]$TasksConfig
    )
    
    Write-SystemMessage -title "Configuring Scheduled Tasks"

    try {

        # Handle task additions
        if ($TasksConfig.Add) {
            foreach ($task in $TasksConfig.Add) {
                Write-SystemMessage -msg "Importing task" -value $task.Name
                Write-Log "Importing task: $($task.Name)" -Level Info
                
                try {
                    # Determine task XML path
                    $taskPath = if ($task.Path -match '^https?://') {
                        # Direct URL
                        $task.Path
                    } else {
                        # Local path or UNC path
                        $task.Path
                    }

                    # Download if it's a URL
                    if ($taskPath -match '^https?://') {
                        $tempPath = Join-Path $env:TEMP "$($task.Name).xml"
                        $script:tempFiles += $tempPath
                        
                        Write-Log "Downloading task XML from: $taskPath" -Level Info
                        Invoke-WebRequest -Uri $taskPath -OutFile $tempPath
                        $taskPath = $tempPath
                    }

                    # Register the task
                    if (Test-Path $taskPath) {
                        Register-ScheduledTask -TaskName $task.Name -Xml (Get-Content $taskPath -Raw) -Force
                        Write-Log "Task imported successfully: $($task.Name)" -Level Info
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "Task XML file not found: $taskPath" -Level Warning
                        Write-SystemMessage -errorMsg -msg "Task XML file not found"
                    }
                } catch {
                    Write-Log "Failed to import task $($task.Name): $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
        }

        if ($TasksConfig.AddRepository) {
            try {
                Write-Log "Adding entire task repository from $($TasksConfig.AddRepository)" -Level Info
                Write-SystemMessage -msg "Adding entire task repository from" -value $($TasksConfig.AddRepository)
                
                # Create temp directory for XML files
                $tempDir = Join-Path $env:TEMP "TaskRepo"
                New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
                
                # Get raw GitHub repository URL
                $repoUrl = $TasksConfig.AddRepository -replace 'github.com', 'raw.githubusercontent.com'
                $repoUrl = $repoUrl -replace '/tree/', '/'
                
                try {
                    # Get list of files from repository
                    $response = Invoke-RestMethod -Uri $repoUrl -UseBasicParsing
                    
                    # Find all XML files
                    $xmlFiles = $response | Where-Object { $_ -match '\.xml$' }
                    
                    foreach ($xmlFile in $xmlFiles) {
                        $fileName = Split-Path $xmlFile -Leaf
                        $fileUrl = "$repoUrl/$fileName"
                        $localPath = Join-Path $tempDir $fileName
                        
                        Write-Log "Downloading task XML: $fileName" -Level Info
                        Write-SystemMessage -msg "Downloading task" -value $fileName
                        
                        # Download XML file
                        Invoke-WebRequest -Uri $fileUrl -OutFile $localPath
                        
                        if (Test-Path $localPath) {
                            # Get task name from filename
                            $taskName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
                            
                            # Register the scheduled task
                            Register-ScheduledTask -TaskName $taskName -Xml (Get-Content $localPath -Raw) -Force
                            Write-Log "Task imported successfully: $taskName" -Level Info
                            Write-SystemMessage -successMsg
                        }
                        else {
                            Write-Log "Failed to download task XML: $fileName" -Level Warning
                            Write-SystemMessage -warningMsg -msg "Failed to download task XML" -value $fileName
                        }
                    }
                }
                catch {
                    Write-Log "Failed to access repository: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg -msg "Failed to access repository"
                }
                finally {
                    # Cleanup temp directory
                    if (Test-Path $tempDir) {
                        Remove-Item -Path $tempDir -Recurse -Force
                    }
                }
            }
            catch {
                Write-Log "Failed to add task repository from $($TasksConfig.AddRepository): $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        

        # Handle task removals
        if ($TasksConfig.Remove) {
            foreach ($task in $TasksConfig.Remove) {
                Write-SystemMessage -msg "Removing task" -value $task.Name
                Write-Log "Removing task: $($task.Name)" -Level Info
                
                try {
                    if (Get-ScheduledTask -TaskName $task.Name -ErrorAction SilentlyContinue) {
                        Unregister-ScheduledTask -TaskName $task.Name -Confirm:$false
                        Write-Log "Task removed successfully: $($task.Name)" -Level Info
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "Task not found: $($task.Name)" -Level Warning
                        Write-SystemMessage -warningMsg -msg "Task not found" -value $task.Name
                    }
                } catch {
                    Write-Log "Failed to remove task $($task.Name): $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
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
        [PSCustomObject]$FontConfig
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
                Write-Log "Font $correctFontName is already installed. Skipping" -Level Info
                Write-SystemMessage -msg "Font $correctFontName is already installed. Skipping"
                continue
            }

            Write-SystemMessage -msg "Installing" -value $correctFontName
            Write-Log "Downloading & Installing $correctFontName from Google Fonts GitHub repository" -Level Info

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
        [PSCustomObject]$TaskbarConfig
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
        if ($TaskbarConfig.DisableMeetNow -eq $true) {
            Write-Log "Disabling Meet Now" -Level Info
            Write-SystemMessage -msg "Disabling Meet Now"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Meet Now: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($TaskbarConfig.DisableMeetNow -eq $false) {
            Write-Log "Enabling Meet Now" -Level Info
            Write-SystemMessage -msg "Enabling Meet Now"
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
        if ($TaskbarConfig.DisableWidgets -eq $true) {
            Write-Log "Disabling Widgets" -Level Info
            Write-SystemMessage -msg "Disabling Widgets"
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Widgets: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($TaskbarConfig.DisableWidgets -eq $false) {
            Write-Log "Enabling Widgets" -Level Info
            Write-SystemMessage -msg "Enabling Widgets"
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
        if ($TaskbarConfig.DisableTaskView -eq $true) {
            Write-Log "Disabling Task View button" -Level Info
            Write-SystemMessage -msg "Disabling Task View button"
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Task View button: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($TaskbarConfig.DisableTaskView -eq $false) {
            Write-Log "Enabling Task View button"
            Write-SystemMessage -msg "Enabling Task View button"
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 1
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable Task View button: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Search
        if ($TaskbarConfig.DisableSearch -eq $true) {
            Write-Log "Disabling Search icon"
            Write-SystemMessage -msg "Disabling Search icon"
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
                Set-RegistryModification -Action add -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSearchBox" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable Search icon: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($TaskbarConfig.DisableSearch -eq $false) {
            Write-Log "Enabling Search icon"
            Write-SystemMessage -msg "Enabling Search icon"
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
        Write-Log "Restarting Explorer to apply taskbar changes"
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
        [PSCustomObject]$PowerConfig
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
        if ($PowerConfig.DisableSleep -eq $true) {
            Write-Log "Disabling sleep" -Level Info
            Write-SystemMessage -msg "Disabling sleep"

            try {
                powercfg /change standby-timeout-ac 0
                powercfg /change standby-timeout-dc 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable sleep: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }

        } elseif ($PowerConfig.DisableSleep -eq $false) {
            Write-Log "Enabling sleep" -Level Info
            Write-SystemMessage -msg "Enabling sleep"
            
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
        if ($PowerConfig.DisableHibernate -eq $true) {
            Write-Log "Disabling hibernate" -Level Info
            Write-SystemMessage -msg "Disabling hibernate"
            try {
                powercfg /hibernate off
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable hibernate: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PowerConfig.DisableHibernate -eq $false) {
            Write-Log "Enabling hibernate" -Level Info
            Write-SystemMessage -msg "Enabling hibernate"
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
        if ($PowerConfig.DisableFastStartup -eq $true) {
            Write-SystemMessage -msg "Disabling fast startup"
            Write-Log "Disabling fast startup" -Level Info
            try {
                Set-RegistryModification -Action add -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable fast startup: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($PowerConfig.DisableFastStartup -eq $false) {
            Write-SystemMessage -msg "Enabling fast startup"
            Write-Log "Enabling fast startup" -Level Info
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
function Set-RegistryItems {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RegistryConfig
    )
    
    try {
        # Process registry additions
        if ($RegistryConfig.Add) {
            Write-SystemMessage -title "Adding Registry Entries"

            # In TOML, Add will be an array of objects
            foreach ($regItem in $RegistryConfig.Add) {
                # Expand environment variables in the value
                $expandedValue = $ExecutionContext.InvokeCommand.ExpandString($regItem.Value)

                Write-SystemMessage -msg "Adding registry entry" -value "Path=$($regItem.Path), Name=$($regItem.Name)"
                Write-Log "Adding registry entry: Path=$($regItem.Path), Name=$($regItem.Name), Type=$($regItem.Type), Value=$expandedValue" -Level Info

                try {
                    if (-not (Test-Path $regItem.Path)) {
                        New-Item -Path $regItem.Path -Force | Out-Null
                        Write-Log "Created registry path: $($regItem.Path)" -Level Info
                    }

                    Set-ItemProperty -Path $regItem.Path -Name $regItem.Name -Value $expandedValue -Type $regItem.Type -Force
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

            # In TOML, Remove will be an array of objects
            foreach ($regItem in $RegistryConfig.Remove) {
                Write-SystemMessage -msg "Removing registry entry" -value "Path=$($regItem.Path), Name=$($regItem.Name)"
                Write-Log "Removing registry entry: Path=$($regItem.Path), Name=$($regItem.Name)" -Level Info

                try {
                    if (Test-Path $regItem.Path) {
                        Remove-ItemProperty -Path $regItem.Path -Name $regItem.Name -Force -ErrorAction Stop
                        Write-SystemMessage -successMsg
                    }
                    else {
                        Write-Log "Registry path not found: $($regItem.Path)" -Level Warning
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
        Write-Log "Error applying registry modifications: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to apply registry modifications. Check the log for details."
        return $false
    }
}

# Function to configure Windows features
function Set-WindowsFeaturesConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$FeaturesConfig
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
        [PSCustomObject]$GoogleConfig
    )

    Write-SystemMessage -title "Configuring Google Workspace"

    try {
        # Configure Drive settings through registry
        $driveFSPath = "HKLM:\Software\Google\DriveFS"
        
        # DefaultWebBrowser
        if ($GoogleConfig.Drive.DefaultWebBrowser) {
            Set-RegistryModification -Action add -Path $driveFSPath -Name "DefaultWebBrowser" -Type String -Value $GoogleConfig.Drive.DefaultWebBrowser | Out-Null
        }
        
        # DisableOnboardingDialog
        if ($GoogleConfig.Drive.DisableOnboardingDialog) {
            Set-RegistryModification -Action add -Path $driveFSPath -Name "DisableOnboardingDialog" -Type DWord -Value 1 | Out-Null
        }
        
        # DisablePhotosSync
        if ($GoogleConfig.Drive.DisablePhotosSync) {
            Set-RegistryModification -Action add -Path $driveFSPath -Name "DisablePhotosSync" -Type DWord -Value 1 | Out-Null
        }
        
        # AutoStartOnLogin
        if ($GoogleConfig.Drive.AutoStartOnLogin) {
            Set-RegistryModification -Action add -Path $driveFSPath -Name "AutoStartOnLogin" -Type DWord -Value 1 | Out-Null
        }
        
        # OpenOfficeFilesInDocs
        if ($GoogleConfig.Drive.OpenOfficeFilesInDocs) {
            Set-RegistryModification -Action add -Path $driveFSPath -Name "OpenOfficeFilesInDocs" -Type DWord -Value 1 | Out-Null
        }

        # Configure Chrome policies through registry
        $chromePolicyPath = "HKLM:\Software\Policies\Google\Chrome"
        
        # CloudManagementEnrollmentToken
        if ($GoogleConfig.Chrome.CloudManagementEnrollmentToken) {
            Set-RegistryModification -Action add -Path $chromePolicyPath -Name "CloudManagementEnrollmentToken" -Type String -Value $GoogleConfig.Chrome.CloudManagementEnrollmentToken | Out-Null
        }
        
        # AlwaysOpenPdfExternally
        if ($GoogleConfig.Chrome.AlwaysOpenPdfExternally) {
            Set-RegistryModification -Action add -Path $chromePolicyPath -Name "AlwaysOpenPdfExternally" -Type DWord -Value 1 | Out-Null
        }
        
        # BrowserSignin
        if ($null -ne $GoogleConfig.Chrome.BrowserSignin) {
            Set-RegistryModification -Action add -Path $chromePolicyPath -Name "BrowserSignin" -Type DWord -Value $GoogleConfig.Chrome.BrowserSignin | Out-Null
        }

        # Google Drive Installation/Uninstallation
        if ($GoogleConfig.Drive.Install -eq $true) {
            if (-not (Test-ProgramInstalled 'Google Drive')) {
                Write-Log "Installing Google Drive" -Level Info
                Write-SystemMessage -msg "Installing Google Drive"

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
            } else {
                Write-Log "Google Drive already installed" -Level Info
                Write-SystemMessage -warningMsg -msg "Google Drive already installed"
            }
        } elseif ($GoogleConfig.Drive.Install -eq $false) {
            Write-Log "Uninstalling Google Drive" -Level Info
            Write-SystemMessage -msg "Uninstalling Google Drive"
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

        # Google Chrome Installation/Uninstallation
        if ($GoogleConfig.Chrome.Install -eq $true) {
            if (-not (Test-ProgramInstalled 'Google Chrome')) {
                Write-Log "Installing Google Chrome" -Level Info
                Write-SystemMessage -msg "Installing Google Chrome"
                
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
            } else {
                Write-Log "Google Chrome already installed" -Level Info
                Write-SystemMessage -warningMsg -msg "Google Chrome already installed"
            }
        } elseif ($GoogleConfig.Chrome.Install -eq $false) {
            Write-Log "Uninstalling Google Chrome" -Level Info
            Write-SystemMessage -msg "Uninstalling Google Chrome"
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
        if ($GoogleConfig.GCPW.Install -eq $true) {
            if (-not (Test-ProgramInstalled 'Google Credential Provider')) {
                if (-not $GoogleConfig.GCPW.EnrollmentToken) {
                    Write-Log "GCPW installation skipped - EnrollmentToken is required but was not provided" -Level Error
                    Write-SystemMessage -errorMsg -msg "GCPW installation requires an EnrollmentToken in the configuration"
                    return $false
                }

                Write-Log "Installing Google Credential Provider for Windows" -Level Info
                Write-SystemMessage -msg "Installing Google Credential Provider for Windows"

                try {
                    $gcpwFileName = if ([Environment]::Is64BitOperatingSystem) {
                        'gcpwstandaloneenterprise64.msi'
                    } else {
                        'gcpwstandaloneenterprise.msi'
                    }
            
                    $gcpwUrl = "https://dl.google.com/credentialprovider/$gcpwFileName"
                    $gcpwPath = Join-Path $env:TEMP $gcpwFileName
                    $script:tempFiles += $gcpwPath

                    Invoke-WebRequest -Uri $gcpwUrl -OutFile $gcpwPath | Out-Null
                    
                    $arguments = "/i `"$gcpwPath`" /quiet"
                    Start-Process msiexec.exe -ArgumentList $arguments -Wait | Out-Null

                    # Configure GCPW settings (enrollment token is required for installation)
                    Set-RegistryModification -Action add -Path "HKLM:\SOFTWARE\Policies\Google\CloudManagement" -Name "EnrollmentToken" -Type String -Value $GoogleConfig.GCPW.EnrollmentToken | Out-Null
                    
                    if ($GoogleConfig.GCPW.DomainsAllowedToLogin) {
                        Set-RegistryModification -Action add -Path "HKLM:\Software\Google\GCPW" -Name "domains_allowed_to_login" -Type String -Value $GoogleConfig.GCPW.DomainsAllowedToLogin | Out-Null
                    }

                    Write-SystemMessage -successMsg
                } catch {
                    Write-Log "Failed to install/configure GCPW: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                    return $false
                } finally {
                    Remove-Item -Path $gcpwPath -Force -ErrorAction SilentlyContinue | Out-Null
                }
            } else {
                Write-Log "Google Credential Provider already installed" -Level Info
                Write-SystemMessage -warningMsg -msg "Google Credential Provider already installed"
            }
        } elseif ($GoogleConfig.GCPW.Install -eq $false) {
            Write-Log "Uninstalling Google Credential Provider for Windows" -Level Info
            Write-SystemMessage -msg "Uninstalling Google Credential Provider for Windows"
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

        Write-Log "Google configuration completed successfully" -Level Info
        return $true
    } catch {
        Write-Log "Error configuring Google products: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to configure Google products. Check the logs for more details."
        return $false
    }
}

# Function to configure Microsoft Office
function Set-OfficeConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$OfficeConfig
    )
    
    Write-SystemMessage -title "Configuring Microsoft Office"

    try {
        # Validate required parameters
        $requiredParams = @('ProductID', 'LanguageID', 'Channel', 'OfficeClientEdition')
        foreach ($param in $requiredParams) {
            if (-not $OfficeConfig.$param) {
                Write-Log "Missing required Office parameter: $param" -Level Error
                Write-SystemMessage -errorMsg -msg "Missing required Office parameter" -value $param
                return $false
            }
        }
        
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
    <Updates Enabled="$(if ($OfficeConfig.UpdatesEnabled -eq $true) { 'TRUE' } elseif ($OfficeConfig.UpdatesEnabled -eq $false) { 'FALSE' } else { throw 'Invalid value. Please use TRUE or FALSE for UpdatesEnabled under the Office section in the configuration file' })" />
    <RemoveMSI />
</Configuration>
"@
        $configPath = Join-Path $env:TEMP "OfficeConfig.xml"
        $configXml | Out-File -FilePath $configPath -Encoding UTF8
        $script:tempFiles += $configPath

        # Download Office Deployment Tool
        Write-SystemMessage -msg "Downloading Office Deployment Tool"
        Write-Log "Downloading Office Deployment Tool"
        
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
        Write-SystemMessage -msg "Extracting Office Deployment Tool"
        Write-Log "Extracting Office Deployment Tool"
        $odtExtractPath = Join-Path $env:TEMP "ODT"
        try {
            Start-Process -FilePath $odtPath -ArgumentList "/quiet /extract:$odtExtractPath" -Wait | Out-Null
            Write-SystemMessage -successMsg
        } catch {
            Write-Log "Failed to extract Office Deployment Tool: $($_.Exception.Message)" -Level Error
            Write-SystemMessage -errorMsg
            return $false
        }

        # Install Office
        Write-SystemMessage -msg "Installing Microsoft Office"
        Write-Log "Installing Microsoft Office"
        $setupPath = Join-Path $odtExtractPath "setup.exe"
        try {
            # Handle SetupReboot parameter if specified
            $setupArgs = "/configure `"$configPath`""
            if ($OfficeConfig.SetupReboot -eq "Never") {
                $setupArgs += " /noreboot"
            }
            
            Start-Process -FilePath $setupPath -ArgumentList $setupArgs -Wait | Out-Null
            Write-SystemMessage -successMsg
        } catch {
            Write-Log "Failed to install Microsoft Office: $($_.Exception.Message)" -Level Error
            Write-SystemMessage -errorMsg
            return $false
        }

        # Activate Office if license key provided
        if ($OfficeConfig.LicenseKey) {
            Write-SystemMessage -msg "Activating Microsoft Office"
            Write-Log "Activating Microsoft Office"
            
            $osppPath = "${env:ProgramFiles}\Microsoft Office\Office16\OSPP.VBS"
            if (Test-Path $osppPath) {
                try {
                    # Clear any existing product keys first
                    Start-Process -FilePath "cscript" -ArgumentList "`"$osppPath`" /dstatus" -Wait -NoNewWindow | Out-Null
                    Start-Process -FilePath "cscript" -ArgumentList "`"$osppPath`" /unpkey:6MWKP" -Wait -NoNewWindow | Out-Null
                    
                    # Install and activate new key
                    Start-Process -FilePath "cscript" -ArgumentList "`"$osppPath`" /inpkey:$($OfficeConfig.LicenseKey)" -Wait -NoNewWindow | Out-Null
                    Start-Sleep -Seconds 2
                    Start-Process -FilePath "cscript" -ArgumentList "`"$osppPath`" /act" -Wait -NoNewWindow | Out-Null
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
        [PSCustomObject]$ThemeConfig
    )

    Write-SystemMessage -title "Configuring Theme Settings"
    
    try {

        # Theme Mode (Dark/Light)
        if ($ThemeConfig.DarkMode) {
            if ($ThemeConfig.DarkMode -eq $true) {
                Write-Log "Enabling dark mode" -Level Info
                Write-SystemMessage -msg "Enabling dark mode"
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
            elseif ($ThemeConfig.DarkMode -eq $false) {
                Write-Log "Enabling light mode" -Level Info
                Write-SystemMessage -msg "Enabling light mode"
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
            if ($ThemeConfig.TransparencyEffects -eq $false) {
                Write-Log "Disabling transparency effects" -Level Info
                Write-SystemMessage -msg "Disabling transparency effects"
                try {
                    Set-RegistryModification -action add -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -name "EnableTransparency" -type "DWord" -value 0
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to disable transparency effects: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
            elseif ($ThemeConfig.TransparencyEffects -eq $true) {
                Write-Log "Enabling transparency effects" -Level Info
                Write-SystemMessage -msg "Enabling transparency effects"
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
            Write-SystemMessage -msg "Setting desktop icon size"
            Write-Log "Setting desktop icon size" -Level Info
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
        Write-Log "Restarting Explorer to apply taskbar changes"
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
        [PSCustomObject]$TweaksConfig
    )
    
    Write-SystemMessage -title "Applying System Tweaks"

    try {

        # Classic Right-Click Menu
        if ($TweaksConfig.ClassicRightClickMenu -eq $true) {
            Write-Log "Enabling classic right-click menu" -Level Info
            Write-SystemMessage -msg "Enabling classic right-click menu"
            try {
                Set-RegistryModification -Action add -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Type String -Value ""
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to enable classic right-click menu: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        } elseif ($TweaksConfig.ClassicRightClickMenu -eq $false) {
            Write-Log "Disabling classic right-click menu" -Level Info
            Write-SystemMessage -msg "Disabling classic right-click menu"
            try {
                Remove-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
                Write-SystemMessage -successMsg
            } catch {
                Write-Log "Failed to disable classic right-click menu: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # God Mode
        if ($TweaksConfig.EnableGodMode -eq $true) {
            Write-Log "Creating God Mode folder" -Level Info
            Write-SystemMessage -msg "Creating God Mode folder"
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
        } elseif ($TweaksConfig.EnableGodMode -eq $false) {
            Write-Log "Removing God Mode folder" -Level Info
            Write-SystemMessage -msg "Removing God Mode folder"
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
        [PSCustomObject]$NetworkConfig
    )
    
    Write-SystemMessage -title "Configuring Network Settings"

    try {
        # Network Discovery
        if ($NetworkConfig.NetworkDiscovery -eq $true) {
            Write-Log "Enabling Network Discovery" -Level Info
            Write-SystemMessage -msg "Enabling Network Discovery"
            try {
                $discoveryRules = Get-NetFirewallRule -Group "@FirewallAPI.dll,-32752" 
                $smbRule = Get-NetFirewallRule -Name "FPS-SMB-In-TCP"
                
                if (($discoveryRules | Where-Object {$_.Enabled -eq $true -and $_.Profile -eq 'Private'}).Count -eq $discoveryRules.Count -and 
                    $smbRule.Enabled -eq $true -and $smbRule.Profile -eq 'Private') {
                    Write-Log "Network Discovery is already enabled for Private profile" -Level Warning
                    Write-SystemMessage -warningMsg -msg "Network Discovery is already enabled for Private profile"
                }
                else {
                    Get-NetFirewallRule -Group "@FirewallAPI.dll,-32752" | Set-NetFirewallRule -Profile Private -Enabled True
                    Set-NetFirewallRule -Name "FPS-SMB-In-TCP" -Profile Private -Enabled True
                    Write-SystemMessage -successMsg
                }
            }
            catch {
                Write-Log "Failed to configure Network Discovery: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($NetworkConfig.NetworkDiscovery -eq $false) {
            Write-Log "Disabling Network Discovery" -Level Info
            Write-SystemMessage -msg "Disabling Network Discovery"
            try {
                $discoveryRules = Get-NetFirewallRule -Group "@FirewallAPI.dll,-32752" 
                $smbRule = Get-NetFirewallRule -Name "FPS-SMB-In-TCP"
                
                if (($discoveryRules | Where-Object {$_.Enabled -eq $false -and $_.Profile -eq 'Private'}).Count -eq $discoveryRules.Count -and 
                    $smbRule.Enabled -eq $false -and $smbRule.Profile -eq 'Private') {
                    Write-Log "Network Discovery is already disabled for Private profile" -Level Warning
                    Write-SystemMessage -warningMsg -msg "Network Discovery is already disabled for Private profile"
                }
                else {
                    Get-NetFirewallRule -Group "@FirewallAPI.dll,-32752" | Set-NetFirewallRule -Profile Private -Enabled False
                    Set-NetFirewallRule -Name "FPS-SMB-In-TCP" -Profile Private -Enabled False
                    Write-SystemMessage -successMsg
                }
            }
            catch {
                Write-Log "Failed to configure Network Discovery: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # File and Printer Sharing
        if ($NetworkConfig.FileAndPrinterSharing -eq $true) {
            Write-Log "Enabling File and Printer Sharing" -Level Info
            Write-SystemMessage -msg "Enabling File and Printer Sharing"
            try {
                $sharingRules = Get-NetFirewallRule -Group "@FirewallAPI.dll,-28502"
                if (($sharingRules | Where-Object {$_.Enabled -eq $true -and $_.Profile -eq 'Private'}).Count -eq $sharingRules.Count) {
                    Write-Log "File and Printer Sharing is already enabled for Private profile" -Level Warning
                    Write-SystemMessage -warningMsg -msg "File and Printer Sharing is already enabled for Private profile"
                }
                else {
                    Get-NetFirewallRule -Group "@FirewallAPI.dll,-28502" | Set-NetFirewallRule -Profile Private -Enabled True
                    Write-SystemMessage -successMsg
                }
            }
            catch {
                Write-Log "Failed to configure File and Printer Sharing: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }
        elseif ($NetworkConfig.FileAndPrinterSharing -eq $false) {
            Write-Log "Disabling File and Printer Sharing" -Level Info
            Write-SystemMessage -msg "Disabling File and Printer Sharing"
            try {
                $sharingRules = Get-NetFirewallRule -Group "@FirewallAPI.dll,-28502"
                if (($sharingRules | Where-Object {$_.Enabled -eq $false -and $_.Profile -eq 'Private'}).Count -eq $sharingRules.Count) {
                    Write-Log "File and Printer Sharing is already disabled for Private profile" -Level Warning
                    Write-SystemMessage -warningMsg -msg "File and Printer Sharing is already disabled for Private profile"
                }
                else {
                    Get-NetFirewallRule -Group "@FirewallAPI.dll,-28502" | Set-NetFirewallRule -Profile Private -Enabled False
                    Write-SystemMessage -successMsg
                }
            }
            catch {
                Write-Log "Failed to configure File and Printer Sharing: $($_.Exception.Message)" -Level Error
                Write-SystemMessage -errorMsg
            }
        }

        # Network Drives
        if ($NetworkConfig.Drives) {
            Write-Log "Mapping network drives" -Level Info
            Write-SystemMessage -msg "Mapping network drives"

            foreach ($driveItem in $NetworkConfig.Drives) {
                if (-not $driveItem.Letter -or -not $driveItem.Path) {
                    Write-Log "Invalid drive mapping: Missing Letter or Path" -Level Warning
                    continue
                }

                $driveLetter = $driveItem.Letter + ":"
                $drivePath = $ExecutionContext.InvokeCommand.ExpandString($driveItem.Path)
                
                Write-Log "Mapping drive $driveLetter to $drivePath" -Level Info
                Write-SystemMessage -msg "Mapping drive $driveLetter to" -value $drivePath

                try {
                    # Build credential object if provided
                    $connectionArgs = @{}
                    if ($driveItem.Credentials) {
                        if ($driveItem.Credentials.Username -and $driveItem.Credentials.Password) {
                            $securePass = ConvertTo-SecureString $driveItem.Credentials.Password -AsPlainText -Force
                            $cred = New-Object System.Management.Automation.PSCredential($driveItem.Credentials.Username, $securePass)
                            $connectionArgs['Credential'] = $cred
                        }
                    }

                    # Test and establish network connection first
                    $sharePath = $drivePath -replace '^([\\]{2}[^\\]+\\[^\\]+).*', '$1'
                    if ($sharePath -match '^\\\\') {
                        Write-Log "Testing network share connection: $sharePath" -Level Info
                        
                        # Remove existing connection if present
                        if (Get-PSDrive -Name $driveItem.Letter -ErrorAction SilentlyContinue) {
                            Remove-PSDrive -Name $driveItem.Letter -Force -ErrorAction SilentlyContinue
                        }
                        net use $driveLetter /delete /y 2>$null
                        
                        # Test network path with credentials
                        if (-not (Test-Path -Path $sharePath @connectionArgs)) {
                            # Try to establish connection
                            if ($connectionArgs['Credential']) {
                                $netUseArgs = "/user:" + $driveItem.Credentials.Username + " " + $driveItem.Credentials.Password
                                $result = net use $sharePath $netUseArgs 2>&1
                                if ($LASTEXITCODE -ne 0) {
                                    throw "Failed to connect to network share: $result"
                                }
                            }
                            else {
                                throw "Network path not accessible: $sharePath"
                            }
                        }
                        
                        Write-Log "Successfully connected to network share" -Level Info
                    }

                    # Now map the drive
                    Write-Log "Mapping drive $driveLetter" -Level Info
                    New-PSDrive -PSProvider FileSystem -Name $driveItem.Letter -Root $drivePath -Persist -ErrorAction Stop @connectionArgs | Out-Null
                    Write-SystemMessage -successMsg
                }
                catch {
                    Write-Log "Failed to map drive $driveLetter : $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg
                }
            }
        }

        Write-Log "Network configuration completed successfully"
        return $true
    }
    catch {
        Write-Log "Error configuring network settings: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to configure network settings. Check the log for details."
        return $false
    }
}

# Function to perform file operations (copy, delete, etc.)
function Set-FileOperations {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$FileConfig
    )

    try {
        Write-SystemMessage -title "Performing File Operations"

        # Copy Operations
        if ($FileConfig.Copy) {
            foreach ($operation in $FileConfig.Copy) {
                Write-SystemMessage -msg "Copying from" -value $operation.Source
                Write-Log "Copying from $($operation.Source) to $($operation.Destination)" -Level Info

                try {
                    # Create destination directory if it doesn't exist
                    $destinationDir = Split-Path -Parent $operation.Destination
                    if (-not (Test-Path $destinationDir)) {
                        New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
                        Write-Log "Created destination directory: $destinationDir" -Level Info
                    }

                    # Copy file or directory
                    if (Test-Path $operation.Source) {
                        Copy-Item -Path $operation.Source -Destination $operation.Destination -Force -Recurse
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "Source not found: $($operation.Source)" -Level Warning
                        Write-SystemMessage -errorMsg -msg "Source not found"
                    }
                } catch {
                    Write-Log "Failed to copy: $($_.Exception.Message)" -Level Warning
                    Write-SystemMessage -errorMsg
                }
            }
        }

        # Move Operations
        if ($FileConfig.Move) {
            foreach ($operation in $FileConfig.Move) {
                Write-SystemMessage -msg "Moving from" -value $operation.Source
                Write-Log "Moving from $($operation.Source) to $($operation.Destination)" -Level Info

                try {
                    # Create destination directory if it doesn't exist
                    $destinationDir = Split-Path -Parent $operation.Destination
                    if (-not (Test-Path $destinationDir)) {
                        New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
                        Write-Log "Created destination directory: $destinationDir" -Level Info
                    }

                    # Move file or directory
                    if (Test-Path $operation.Source) {
                        Move-Item -Path $operation.Source -Destination $operation.Destination -Force
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "Source not found: $($operation.Source)" -Level Warning
                        Write-SystemMessage -errorMsg -msg "Source not found"
                    }
                } catch {
                    Write-Log "Failed to move: $($_.Exception.Message)" -Level Warning
                    Write-SystemMessage -errorMsg
                }
            }
        }

        # Rename Operations
        if ($FileConfig.Rename) {
            foreach ($operation in $FileConfig.Rename) {
                Write-SystemMessage -msg "Renaming" -value $operation.Source
                Write-Log "Renaming $($operation.Source) to $($operation.NewName)" -Level Info

                try {
                    if (Test-Path $operation.Source) {
                        Rename-Item -Path $operation.Source -NewName $operation.NewName -Force
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "Source not found: $($operation.Source)" -Level Warning
                        Write-SystemMessage -errorMsg -msg "Source not found"
                    }
                } catch {
                    Write-Log "Failed to rename: $($_.Exception.Message)" -Level Warning
                    Write-SystemMessage -errorMsg
                }
            }
        }

        # New File/Folder Operations
        if ($FileConfig.New) {
            foreach ($operation in $FileConfig.New) {
                Write-SystemMessage -msg "Creating new" -value "$($operation.Type): $($operation.Path)"
                Write-Log "Creating new $($operation.Type): $($operation.Path)" -Level Info

                try {
                    # Create parent directory if it doesn't exist
                    $parentDir = Split-Path -Parent $operation.Path
                    if (-not (Test-Path $parentDir)) {
                        New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
                        Write-Log "Created parent directory: $parentDir" -Level Info
                    }

                    # Create file or folder
                    switch ($operation.Type) {
                        "File" {
                            if (-not (Test-Path $operation.Path)) {
                                New-Item -Path $operation.Path -ItemType File -Force | Out-Null
                                Write-SystemMessage -successMsg
                            } else {
                                Write-Log "File already exists: $($operation.Path)" -Level Warning
                                Write-SystemMessage -warningMsg -msg "File already exists"
                            }
                        }
                        "Folder" {
                            if (-not (Test-Path $operation.Path)) {
                                New-Item -Path $operation.Path -ItemType Directory -Force | Out-Null
                                Write-SystemMessage -successMsg
                            } else {
                                Write-Log "Folder already exists: $($operation.Path)" -Level Warning
                                Write-SystemMessage -warningMsg -msg "Folder already exists"
                            }
                        }
                        default {
                            Write-Log "Invalid type specified: $($operation.Type)" -Level Error
                            Write-SystemMessage -errorMsg -msg "Invalid type specified"
                        }
                    }
                } catch {
                    Write-Log "Failed to create $($operation.Type): $($_.Exception.Message)" -Level Warning
                    Write-SystemMessage -errorMsg
                }
            }
        }

        # Delete Operations
        if ($FileConfig.Delete) {
            foreach ($operation in $FileConfig.Delete) {
                Write-SystemMessage -msg "Deleting" -value $operation.Path
                Write-Log "Deleting: $($operation.Path)" -Level Info

                try {
                    if (Test-Path $operation.Path) {
                        # Check if item is read-only or system
                        $item = Get-Item $operation.Path
                        if ($item.Attributes -match "ReadOnly|System") {
                            Write-Log "Warning: Attempting to delete protected item: $($operation.Path)" -Level Warning
                            Write-SystemMessage -warningMsg -msg "Attempting to delete protected item"
                        }

                        Remove-Item -Path $operation.Path -Force -Recurse
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "Path not found: $($operation.Path)" -Level Warning
                        Write-SystemMessage -warningMsg -msg "Path not found"
                    }
                } catch {
                    Write-Log "Failed to delete: $($_.Exception.Message)" -Level Warning
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
        [PSCustomObject]$ShortcutConfig
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


            # Expand environment variables in paths
            $expandedTarget = [Environment]::ExpandEnvironmentVariables($shortcut.Target)
            $expandedWorkingDir = if ($shortcut.WorkingDirectory) {
                [Environment]::ExpandEnvironmentVariables($shortcut.WorkingDirectory)
            } else {
                $null
            }

            # Validate target path exists
            if (-not (Test-Path $expandedTarget)) {
                Write-Log "Target path does not exist: $expandedTarget" -Level Error
                Write-SystemMessage -errorMsg -msg "Target path does not exist"
                continue
            }

            try {
                # Determine shortcut location
                $shortcutLocation = switch ($shortcut.Location) {
                    "Desktop" { [Environment]::GetFolderPath("Desktop") }
                    "StartMenu" { [Environment]::GetFolderPath("StartMenu") }
                    "Programs" { [Environment]::GetFolderPath("Programs") }
                    "CommonDesktop" { [Environment]::GetFolderPath("CommonDesktop") }
                    "CommonStartMenu" { [Environment]::GetFolderPath("CommonStartMenu") }
                    "CommonPrograms" { [Environment]::GetFolderPath("CommonPrograms") }
                    "Startup" { [Environment]::GetFolderPath("Startup") }
                    "CommonStartup" { [Environment]::GetFolderPath("CommonStartup") }
                    default { 
                        if ($shortcut.Location -and (Test-Path $shortcut.Location)) {
                            $shortcut.Location
                        } else {
                            Write-Log "Invalid shortcut location specified: $($shortcut.Location)" -Level Warning
                            return
                        }
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
                $Shortcut.TargetPath = $expandedTarget
                
                if ($shortcut.Arguments) {
                    Write-Log "Setting shortcut arguments: $($shortcut.Arguments)" -Level Info
                    $Shortcut.Arguments = $shortcut.Arguments
                }
                
                if ($expandedWorkingDir) {
                    # Validate working directory exists
                    if (-not (Test-Path $expandedWorkingDir)) {
                        Write-Log "Working directory does not exist: $expandedWorkingDir" -Level Warning
                        Write-SystemMessage -warningMsg -msg "Working directory does not exist, using target directory"
                        $Shortcut.WorkingDirectory = Split-Path -Parent $expandedTarget
                    } else {
                        Write-Log "Setting working directory: $expandedWorkingDir" -Level Info
                        $Shortcut.WorkingDirectory = $expandedWorkingDir
                    }
                }
                
                # Only set custom icon if specified
                if ($shortcut.IconPath) {
                    # Parse icon location and index
                    $iconParts = $shortcut.IconPath -split ','
                    $iconPath = [Environment]::ExpandEnvironmentVariables($iconParts[0])
                    $iconIndex = if ($iconParts.Count -gt 1) { $iconParts[1] } else { "0" }

                    # Only set if icon file exists
                    if (Test-Path $iconPath) {
                        Write-Log "Setting custom icon: $iconPath,$iconIndex" -Level Info
                        $Shortcut.IconPath = "$iconPath,$iconIndex"
                    } else {
                        Write-Log "Custom icon file not found: $iconPath, using default icon" -Level Info
                    }
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

function Remove-Bloatware {
    try {
        Write-SystemMessage -title "Removing Bloatware"
        Write-Log "Starting bloatware removal process" -Level Info

        # Define list of bloatware apps to remove
        $bloatwareApps = @(
            # Microsoft apps
            "Microsoft.3DBuilder",
            "Microsoft.549981C3F5F10",  # Cortana app
            "Microsoft.Copilot",
            "Microsoft.Messaging",
            "Microsoft.BingFinance",
            "Microsoft.BingFoodAndDrink",
            "Microsoft.BingHealthAndFitness",
            "Microsoft.BingNews",
            "Microsoft.BingSports",
            "Microsoft.BingTravel",
            "Microsoft.MicrosoftOfficeHub",
            "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.News",
            "Microsoft.MixedReality.Portal",
            "Microsoft.Office.OneNote",
            "Microsoft.OutlookForWindows",
            "Microsoft.Office.Sway",
            "Microsoft.OneConnect",
            "Microsoft.People",
            "Microsoft.SkypeApp",
            "Microsoft.Todos",
            "Microsoft.WindowsMaps",
            "Microsoft.ZuneVideo",
            "Microsoft.ZuneMusic",
            "MicrosoftCorporationII.MicrosoftFamily",  # Family Safety App
            "MSTeams",
            "Outlook",  # New Outlook app
            "LinkedInforWindows",  # LinkedIn app
            "Microsoft.XboxApp",
            "Microsoft.XboxGamingOverlay",
            "Microsoft.Xbox.TCUI",
            "Microsoft.XboxGameOverlay",
            "Microsoft.WindowsCommunicationsApps",  # Mail app
            "Microsoft.YourPhone",  # Phone Link (Your Phone)
            "MicrosoftCorporationII.QuickAssist",  # Quick Assist

            # Third-party apps
            "ACGMediaPlayer",
            "ActiproSoftwareLLC",
            "AdobeSystemsIncorporated.AdobePhotoshopExpress",
            "Amazon.com.Amazon",
            "AmazonVideo.PrimeVideo",
            "Asphalt8Airborne",
            "AutodeskSketchBook",
            "CaesarsSlotsFreeCasino",
            "COOKINGFEVER",
            "CyberLinkMediaSuiteEssentials",
            "DisneyMagicKingdoms",
            "Disney",
            "DrawboardPDF",
            "Duolingo-LearnLanguagesforFree",
            "EclipseManager",
            "Facebook",
            "FarmVille2CountryEscape",
            "fitbit",
            "Flipboard",
            "HiddenCity",
            "HULULLC.HULUPLUS",
            "iHeartRadio",
            "Instagram",
            "king.com.BubbleWitch3Saga",
            "king.com.CandyCrushSaga",
            "king.com.CandyCrushSodaSaga",
            "MarchofEmpires",
            "Netflix",
            "NYTCrossword",
            "OneCalendar",
            "PandoraMediaInc",
            "PhototasticCollage",
            "PicsArt-PhotoStudio",
            "Plex",
            "PolarrPhotoEditorAcademicEdition",
            "RoyalRevolt",
            "Shazam",
            "Sidia.LiveWallpaper",
            "SlingTV",
            "Spotify",
            "TikTok",
            "TuneInRadio",
            "Twitter",
            "Viber",
            "WinZipUniversal",
            "Wunderlist",
            "XING"
        )

        # Get list of currently installed apps that match our bloatware list
        $installedBloatware = @()
        foreach ($appName in $bloatwareApps) {
            if (Get-AppxPackage -AllUsers -Name $appName -ErrorAction SilentlyContinue) {
                $installedBloatware += $appName
            }
            # Also check provisioned packages
            elseif (Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $appName }) {
                $installedBloatware += $appName
            }
        }

        $totalApps = $installedBloatware.Count
        Write-Log "Found $totalApps bloatware apps to process" -Level Info
        Write-SystemMessage -msg "Total bloatware apps found to remove" -value $totalApps -msgColor Yellow

        $currentApp = 0
        foreach ($appName in $installedBloatware) {
            $currentApp++
            Write-Log "Processing ($currentApp/$totalApps): $appName" -Level Info
            Write-SystemMessage -msg "Removing app" -value $appName

            # First remove for all users
            $appInstance = Get-AppxPackage -AllUsers -Name $appName -ErrorAction SilentlyContinue
            if ($appInstance) {
                try {
                    Get-AppxPackage -AllUsers -Name $appName | Remove-AppxPackage -AllUsers -ErrorAction Stop
                    Write-Log "Successfully removed $appName" -Level Info
                    Write-SystemMessage -successMsg
                } catch {
                    $errorMessage = "Failed to remove $appName`: $($_.Exception.Message)"
                    Write-Log $errorMessage -Level Error
                    Write-SystemMessage -errorMsg -msg "Failed to remove app"
                    continue
                }
            } else {
                Write-Log "$appName not found as installed package" -Level Info
                Write-SystemMessage -warningMsg -msg "App not found"
            }

            # Then remove provisioned package to prevent reinstallation
            $provPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $appName }
            if ($provPackage) {
                Write-SystemMessage -msg "Removing provisioned package" -value $provPackage.PackageName
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $provPackage.PackageName -ErrorAction Stop
                    Write-Log "Provisioned package $appName removed successfully" -Level Info
                    Write-SystemMessage -successMsg
                } catch {
                    $errorMessage = "Failed to remove provisioned package $appName`: $($_.Exception.Message)"
                    Write-Log $errorMessage -Level Error
                    Write-SystemMessage -errorMsg -msg "Failed to remove provisioned package"
                }
            }
        }

        # Handle MSEdge uninstallation if specified
        if ($AppConfig.RemoveMSEdge -eq $true) {
            Write-SystemMessage -msg "Removing Microsoft Edge"
            Write-Log "Starting Microsoft Edge removal process" -Level Info

            try {
                # Stop Edge processes
                Get-Process -Name msedge -ErrorAction SilentlyContinue | Stop-Process -Force

                # Get Edge installation path
                $edgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\*\Installer\setup.exe"
                if (Test-Path $edgePath) {
                    $setupExe = Get-Item $edgePath | Select-Object -ExpandProperty FullName
                    if ($setupExe) {
                        # Uninstall Edge
                        $uninstallArgs = "--uninstall --system-level --verbose-logging --force-uninstall"
                        Start-Process -FilePath $setupExe -ArgumentList $uninstallArgs -Wait -NoNewWindow
                        Write-Log "Microsoft Edge uninstallation completed" -Level Info
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "Microsoft Edge setup.exe not found" -Level Warning
                        Write-SystemMessage -warningMsg -msg "Edge uninstaller not found"
                    }
                } else {
                    Write-Log "Microsoft Edge installation not found" -Level Warning
                    Write-SystemMessage -warningMsg -msg "Edge installation not found"
                }
            } catch {
                Write-Log "Failed to uninstall Microsoft Edge: $_" -Level Error
                Write-SystemMessage -errorMsg -msg "Failed to remove Microsoft Edge"
            }
        }

        Write-Log "Bloatware removal process completed" -Level Info
        return $true

    } catch {
        $errorMessage = "An error occurred during bloatware removal: $($_.Exception.Message)"
        Write-Log $errorMessage -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to remove bloatware. Check the logs for details."
        return $false
    }
}

# Function to install language packs
function Set-LanguageConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$SystemConfig
    )

    try {
        # Handle language packs if specified
        if ($SystemConfig.LanguagePacks) {
            Write-SystemMessage -msg "Installing language packs..."
            Write-Log "Installing language packs..." -Level Info

            foreach ($langPack in $SystemConfig.LanguagePacks) {
                $langId = $langPack.LanguageId
                Write-SystemMessage -msg "Installing language pack" -value $langId
                Write-Log "Installing language pack: $langId" -Level Info

                # Check if language pack is already installed
                $installed = Get-WindowsCapability -Online | Where-Object { 
                    $_.Name -like "Language.Basic~~~$langId~*" -and $_.State -eq "Installed" 
                }

                if (-not $installed) {
                    # Install basic language support
                    $basicLang = Get-WindowsCapability -Online | Where-Object { 
                        $_.Name -like "Language.Basic~~~$langId~*" 
                    } | Select-Object -First 1

                    if ($basicLang) {
                        Add-WindowsCapability -Online -Name $basicLang.Name
                        Write-Log "Installed basic language support for: $langId" -Level Info
                    } else {
                        Write-Log "Basic language support not found for: $langId" -Level Warning
                    }

                    # Install additional features if specified
                    if ($langPack.Features) {
                        foreach ($feature in $langPack.Features) {
                            $featureCap = Get-WindowsCapability -Online | Where-Object {
                                $_.Name -like "Language.$feature~~~$langId~*"
                            } | Select-Object -First 1

                            if ($featureCap) {
                                Add-WindowsCapability -Online -Name $featureCap.Name
                                Write-Log "Installed $feature for language: $langId" -Level Info
                            } else {
                                Write-Log "$feature not found for language: $langId" -Level Warning
                            }
                        }
                    }
                } else {
                    Write-SystemMessage -warningMsg -msg "Language pack already installed" -value $langId
                    Write-Log "Language pack already installed: $langId" -Level Warning
                }
            }
        }


    } catch {
        Write-Log "Error in Set-LanguageConfiguration: $_" -Level Error
        throw
    }
}

# Function to execute commands from configuration
function Set-Commands {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$CommandConfig
    )

    try {
        Write-SystemMessage -title "Executing Commands"
        $success = $true

        # Handle Run commands
        if ($CommandConfig.Run) {
            Write-SystemMessage -msg "Processing Run commands..."
            foreach ($run in $CommandConfig.Run) {
                Write-Log "Executing program: $($run.Program) with arguments: $($run.Arguments)" -Level Info
                Write-SystemMessage -msg "Running" -value $run.Program

                try {
                    $programPath = $run.Program
                    # If not a full path, try to resolve it
                    if (-not $programPath.Contains("\\") -and -not (Test-Path $programPath)) {
                        $programPath = (Get-Command $run.Program -ErrorAction SilentlyContinue).Source
                    }

                    if ($programPath) {
                        Start-Process -FilePath $programPath -ArgumentList $run.Arguments -Wait -NoNewWindow
                        Write-SystemMessage -successMsg
                    } else {
                        Write-Log "Program not found: $($run.Program)" -Level Error
                        Write-SystemMessage -errorMsg -msg "Program not found"
                        $success = $false
                    }
                } catch {
                    Write-Log "Failed to execute program $($run.Program): $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg -msg "Failed to execute program"
                    $success = $false
                }
            }
        }

        # Handle CMD commands
        if ($CommandConfig.Cmd) {
            Write-SystemMessage -msg "Processing CMD commands..."
            foreach ($run in $CommandConfig.Cmd) {
                Write-Log "Executing CMD command: $($run.Command)" -Level Info
                Write-SystemMessage -msg "Running CMD command" -value $run.Command

                try {
                    $result = cmd.exe /c $run.Command
                    if ($LASTEXITCODE -eq 0) {
                        Write-SystemMessage -successMsg
                        if ($result) {
                            Write-Log "Command output: $result" -Level Info
                        }
                    } else {
                        Write-Log "CMD command failed with exit code: $LASTEXITCODE" -Level Error
                        Write-SystemMessage -errorMsg
                        $success = $false
                    }
                } catch {
                    Write-Log "Failed to execute CMD command: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg -msg "Failed to execute CMD command"
                    $success = $false
                }
            }
        }

        # Handle PowerShell commands
        if ($CommandConfig.Powershell) {
            Write-SystemMessage -msg "Processing PowerShell commands..."
            foreach ($run in $CommandConfig.Powershell) {
                Write-Log "Executing PowerShell command: $($run.Command)" -Level Info
                Write-SystemMessage -msg "Running PowerShell command" -value $run.Command

                try {
                    $scriptBlock = [ScriptBlock]::Create($run.Command)
                    $result = Invoke-Command -ScriptBlock $scriptBlock
                    Write-SystemMessage -successMsg
                    if ($result) {
                        Write-Log "Command output: $result" -Level Info
                    }
                } catch {
                    Write-Log "Failed to execute PowerShell command: $($_.Exception.Message)" -Level Error
                    Write-SystemMessage -errorMsg -msg "Failed to execute PowerShell command"
                    $success = $false
                }
            }
        }

        Write-Log "Command execution completed" -Level Info
        return $success
    }
    catch {
        Write-Log "Error executing commands: $($_.Exception.Message)" -Level Error
        Write-SystemMessage -errorMsg -msg "Failed to execute commands. Check the logs for details."
        return $false
    }
}

# Main Execution Block
try {
    Clear-Host
    Show-SplashScreen -version $winforgeVersion

    # Check PowerShell version first
    $requiredPSVersion = "5.1"
    if ($PSVersionTable.PSVersion -lt [Version]$requiredPSVersion) {
        Write-Log "PowerShell version $requiredPSVersion or higher is required. Current version: $($PSVersionTable.PSVersion)" -Level Error
        throw "PowerShell version $requiredPSVersion or higher is required. Current version: $($PSVersionTable.PSVersion)"
    }

    # Verify running as administrator
    if (-not (Test-AdminPrivileges)) {
        throw "This script requires administrative privileges"
    }

    # Check for required modules
    if (-not (Test-RequiredModules)) {
        Write-Log "Required modules are not available. Attempting to install them now."
        Install-RequiredModules
    }

    # Initialize configuration status hashtable with counts
    $configStatus = @{}

    # Load and validate configuration
    $configData = Read-ConfigFile -Path $ConfigPath

    # Set System Checkpoint
    Set-SystemCheckpoint

    # System Configuration
    if ($configData.System) {
        $configStatus['System'] = Set-SystemConfiguration -SystemConfig $configData.System
    }

    # Windows Activation
    if ($configData.Activation) {
        $configStatus['Activation'] = Set-WindowsActivation -ActivationConfig $configData.Activation
    }

    # Environment Variables
    if ($configData.EnvironmentVariables) {
        $configStatus['Environment'] = Set-EnvironmentVariables -EnvConfig $configData.EnvironmentVariables
    }

    # Taskbar Configuration
    if ($configData.Taskbar) {
        $configStatus['Taskbar'] = Set-TaskbarConfiguration -TaskbarConfig $configData.Taskbar
    }

    # Theme Configuration
    if ($configData.Theme) {
        $configStatus['Theme'] = Set-ThemeConfiguration -ThemeConfig $configData.Theme
    }

    # System Tweaks
    if ($configData.Tweaks) {
        $configStatus['Tweaks'] = Set-TweaksConfiguration -TweaksConfig $configData.Tweaks
    }

    # Power
    if ($configData.Power) {
        $configStatus['Power'] = Set-PowerConfiguration -PowerConfig $configData.Power
    }

    # Network Configuration
    if ($configData.Network) {
        $configStatus['Network'] = Set-NetworkConfiguration -NetworkConfig $configData.Network
    }

    # Privacy
    if ($configData.Privacy) {
        $configStatus['Privacy'] = Set-PrivacyConfiguration -PrivacyConfig $configData.Privacy
    }

    # Security
    if ($configData.Security) {
        $configStatus['Security'] = Set-SecurityConfiguration -SecurityConfig $configData.Security
    }

    # Windows Update
    if ($configData.WindowsUpdate) {
        $configStatus['WindowsUpdate'] = Set-WindowsUpdateConfiguration -UpdateConfig $configData.WindowsUpdate
    }

    # Windows Features
    if ($configData.WindowsFeatures) {
        $configStatus['WindowsFeatures'] = Set-WindowsFeaturesConfiguration -FeaturesConfig $configData.WindowsFeatures
    }

    # Fonts installation
    if ($configData.Fonts) {
        $configStatus['Fonts'] = Install-Fonts -FontConfig $configData.Fonts
    }

    # Application Management
    if ($configData.Applications) {
        if ($configData.Applications.Install) {
            $configStatus['ApplicationInstall'] = Install-Applications -AppConfig $configData.Applications.Install
        }
        if ($configData.Applications.Uninstall) {
            $configStatus['ApplicationUninstall'] = Remove-Applications -AppConfig $configData.Applications.Uninstall
        }

        if ($configData.Applications.RemoveBloatware -eq $true) {
            $configStatus['Bloatware'] = Remove-Bloatware
        }
    }

    # Google Configuration
    if ($configData.Google) {
        $configStatus['Google'] = Set-GoogleConfiguration -GoogleConfig $configData.Google
    }

    # Office Configuration
    if ($configData.Office) {
        $configStatus['Office'] = Set-OfficeConfiguration -OfficeConfig $configData.Office
    }

    # Registry modifications
    if ($configData.Registry) {
        $configStatus['Registry'] = Set-RegistryItems -RegistryConfig $configData.Registry
    }

    # Scheduled Tasks
    if ($configData.Tasks) {
        $configStatus['Tasks'] = Set-ScheduledTasksConfiguration -TasksConfig $configData.Tasks
    }

    # File Operations
    if ($configData.Files) {
        $configStatus['Files'] = Set-FileOperations -FileConfig $configData.Files
    }

    # Shortcuts
    if ($configData.Shortcuts) {
        $configStatus['Shortcuts'] = Set-Shortcuts -ShortcutConfig $configData.Shortcuts
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
                    Write-SystemMessage -msg "Restarting system"
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
            Write-SystemMessage -msg "Cleaning up temporary files"
            Write-Log "Cleaning up temporary files"
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
    exit 0
}
catch {
    Write-Log "$($_.Exception.Message)" -Level Error
    Write-SystemMessage -errorMsg -msg "$($_.Exception.Message)"
    Pause
    exit 1
}