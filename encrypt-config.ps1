<#
.SYNOPSIS
    Encryption utility for YAML files.
.DESCRIPTION
    Encryption utility for YAML files.
    Supports local and remote configurations with validation.

.PARAMETER ConfigPath
    Path to the configuration file (local .yaml/.yml file only)

.PARAMETER Encrypt
    Encrypt the file.

.PARAMETER Decrypt
    Decrypt the file.

.EXAMPLE
    .\Encryption-Utility.ps1 -ConfigPath "myconfig.yaml" -Encrypt

.EXAMPLE
    .\Encryption-Utility.ps1 -ConfigPath "myconfig.yaml" -Decrypt

.NOTES
    Password can't be parsed as a parameter, so it's not included in the parameter set always prompts for password via read-host secure
#>


[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [Alias("config")]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false)]
    [switch]$Encrypt,

    [Parameter(Mandatory = $false)]
    [switch]$Decrypt,

    [Parameter(Mandatory = $false)]
    [System.Security.SecureString]$Password
)

# Function to test if a file is encrypted
function Test-EncryptedConfig {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )
    
    try {
        if (-not (Test-Path $ConfigPath)) { return $false }
        $content = Get-Content $ConfigPath -Raw -ErrorAction Stop
        try {
            $package = $content | ConvertFrom-Json
            return ($null -ne $package.Salt -and 
                   $null -ne $package.Data -and 
                   $null -ne $package.IV)
        }
        catch {
            return $false
        }
    }
    catch {
        return $false
    }
}

# Function to encrypt/decrypt files
function Convert-SecureConfig {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath,
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
            if (-not (Test-Path $ConfigPath)) {
                throw "File not found: $ConfigPath"
            }

            # Get file content
            $configContent = Get-Content $ConfigPath -Raw

            # Use a temporary file for encrypted content
            $tempFile = "$ConfigPath.tmp"

            if ($IsEncrypting) {
                # Check if already encrypted
                if (Test-EncryptedConfig -ConfigPath $ConfigPath) {
                    throw "File is already encrypted. Decrypt it first if you want to re-encrypt."
                }

                # Generate unique random salt
                $salt = New-Object byte[] 32
                $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
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
                        
                        # Save encrypted content to temp file first
                        $package | Set-Content $tempFile
                        
                        # Move temp file to final location
                        Move-Item -Path $tempFile -Destination $ConfigPath -Force
                        Write-Host "File encrypted successfully: $ConfigPath"
                        
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
                    Write-Host "Attempting to decrypt file..."
                    
                    # Parse the encrypted package
                    $package = Get-Content $ConfigPath -Raw | ConvertFrom-Json
                    $salt = [Convert]::FromBase64String($package.Salt)
                    $encrypted = [Convert]::FromBase64String($package.Data)
                    $iv = [Convert]::FromBase64String($package.IV)

                    # Recreate key from password and salt
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
                                
                                # Save decrypted content to temp file first
                                $decryptedContent | Set-Content $tempFile -NoNewline
                                
                                # Move temp file to final location
                                Move-Item -Path $tempFile -Destination $ConfigPath -Force
                                Write-Host "File decrypted successfully: $ConfigPath"
                                
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
                    return $false
                }
            }
        }
        finally {
            # Clean up temp file if it exists
            if (Test-Path $tempFile) {
                Remove-Item $tempFile -Force
            }
            
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
        return $false
    }
}

# If no parameters provided, prompt for them
if (-not $ConfigPath) {
    $ConfigPath = Read-Host "Enter path to a YAML configuration file"
}

if (-not $Encrypt -and -not $Decrypt) {
    $operation = Read-Host "Type 'Encrypt' to encrypt or 'Decrypt' to decrypt"
    switch ($operation.ToLower()) {
        "encrypt" { $Encrypt = $true }
        "decrypt" { $Decrypt = $true }
        default {
            Write-Host "Invalid operation. Please specify either 'Encrypt' or 'Decrypt'"
            exit 0
        }
    }
}

if ($Encrypt) {
    Write-Host "Enter password to encrypt the file:"
    $password = Read-Host -AsSecureString
    Write-Host "Re-enter password to confirm:"
    $confirmPassword = Read-Host -AsSecureString
    
    # Convert SecureString to plain text for comparison
    $BSTR1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword)
    $pass1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR1)
    $pass2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)
    
    # Clean up BSTR objects
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR1)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR2)
    
    if ($pass1 -ne $pass2) {
        Write-Host "Passwords do not match"
        exit 0
    }
    
    # Clean up plain text passwords
    $pass1 = "0" * $pass1.Length
    $pass2 = "0" * $pass2.Length
    Remove-Variable pass1, pass2
    
    $result = Convert-SecureConfig -ConfigPath $ConfigPath -IsEncrypting $true -Password $password
    if (-not $result) {
        exit 0
    }
}
elseif ($Decrypt) {
    Write-Host "Enter password to decrypt the file:"
    $password = Read-Host -AsSecureString
    
    $result = Convert-SecureConfig -ConfigPath $ConfigPath -IsEncrypting $false -Password $password
    if (-not $result) {
        exit 0
    }
}