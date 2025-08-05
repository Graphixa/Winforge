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

# Parameter validation for interactive mode
if (-not $ConfigPath) {
    Write-Host "No configuration file specified." -ForegroundColor Yellow
    Write-Host # Spacing
    $ConfigPath = Read-Host "Enter path to a YAML configuration file"
    
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        Write-Error "No configuration file provided. Exiting."
        exit 1
    }
}

# Operation detection when neither Encrypt nor Decrypt is specified
if (-not $Encrypt -and -not $Decrypt) {
    Write-Host "No operation specified." -ForegroundColor Yellow
    Write-Host # Spacing
    $operation = Read-Host "Type `"Encrypt`" to encrypt or `"Decrypt`" to decrypt"
    switch ($operation.ToLower()) {
        'encrypt' { $Encrypt = $true }
        'decrypt' { $Decrypt = $true }
        default { 
            Write-Error "Invalid operation. Please enter 'encrypt' or 'decrypt'. Exiting."
            exit 1 
        }
    }
}

# Validate that only one operation is specified
if ($Encrypt -and $Decrypt) {
    Write-Error "Cannot specify both Encrypt and Decrypt operations. Please choose one."
    exit 1
}

function Test-EncryptedConfig {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )
    
    try {
        # Try to parse the content as JSON
        $content = Get-Content $ConfigPath -Raw
        $package = $content | ConvertFrom-Json

        # Check if it has our expected structure
        return ($null -ne $package.Salt -and 
                $null -ne $package.Data -and 
                $null -ne $package.IV)
    }
    catch {
        return $false
    }
}

function Test-YAMLFile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )
    
    try {
        # Check file extension
        $extension = [System.IO.Path]::GetExtension($ConfigPath).ToLower()
        if ($extension -notin @('.yaml', '.yml')) {
            Write-Warning "File extension '$extension' is not a standard YAML extension (.yaml/.yml)"
            return $false
        }
        
        # Basic YAML syntax validation
        $content = Get-Content $ConfigPath -Raw
        if ([string]::IsNullOrWhiteSpace($content)) {
            Write-Warning "File is empty"
            return $false
        }
        
        # Check for basic YAML structure indicators
        if ($content -match '^[\s]*[\w\-]+[\s]*:' -or $content -match '^[\s]*-[\s]+') {
            return $true
        }
        
        Write-Warning "File does not appear to contain valid YAML structure"
        return $false
    }
    catch {
        Write-Warning "Error validating YAML file: $($_.Exception.Message)"
        return $false
    }
}

# First check if file exists
if (-not (Test-Path $ConfigPath)) {
    Write-Error "File not found: $ConfigPath"
    exit 1
}

# Validate YAML file format for non-encrypted files
if ($Encrypt) {
    $isEncrypted = Test-EncryptedConfig -ConfigPath $ConfigPath
    if (-not $isEncrypted) {
        $isValidYAML = Test-YAMLFile -ConfigPath $ConfigPath
        if (-not $isValidYAML) {
            $continue = Read-Host "File may not be valid YAML. Continue anyway? (y/N)"
            if ($continue -ne 'y' -and $continue -ne 'Y') {
                Write-Host "Operation cancelled by user"
                exit 0
            }
        }
    }
}

# Check encryption status based on operation
if ($Decrypt) {
    $isEncrypted = Test-EncryptedConfig -ConfigPath $ConfigPath
    if (-not $isEncrypted) {
        Write-Host "File is not encrypted. Skipping decryption."
        exit 0
    }
}
elseif ($Encrypt) {
    $isEncrypted = Test-EncryptedConfig -ConfigPath $ConfigPath
    if ($isEncrypted) {
        Write-Error "File is already encrypted. Decrypt it first if you want to re-encrypt."
        exit 1
    }
}

# Only prompt for password if not provided
if (-not $Password) {
    if ($Encrypt) {
        # For encryption, ask for password twice
        $passwordsMatch = $false
        $attemptCount = 0
        while (-not $passwordsMatch -and $attemptCount -lt 3) {
            $attemptCount++
            $securePassword1 = Read-Host -Prompt "Enter password" -AsSecureString
            $securePassword2 = Read-Host -Prompt "Re-enter password" -AsSecureString
            
            # Check if passwords are empty/null
            if (-not $securePassword1 -or $securePassword1.Length -eq 0) {
                Write-Host "Password cannot be empty. Please enter a valid password." -ForegroundColor Red
                continue
            }
            
            if (-not $securePassword2 -or $securePassword2.Length -eq 0) {
                Write-Host "Password confirmation cannot be empty. Please enter a valid password." -ForegroundColor Red
                continue
            }
            
            $BSTR1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword1)
            $BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword2)
            
            try {
                $pass1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR1)
                $pass2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)
                
                # Validate password strength
                if ($pass1.Length -lt 8) {
                    Write-Host "Password must be at least 8 characters long. Please try again."
                    continue
                }
                
                if ($pass1 -eq $pass2) {
                    $Password = $securePassword1
                    $passwordsMatch = $true
                }
                else {
                    Write-Host "Passwords do not match. Please try again."
                }
            }
            finally {
                # Clean up the passwords from memory
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR1)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR2)
                if ($pass1) { $pass1 = "0" * $pass1.Length }
                if ($pass2) { $pass2 = "0" * $pass2.Length }
                Remove-Variable -Name pass1 -ErrorAction SilentlyContinue
                Remove-Variable -Name pass2 -ErrorAction SilentlyContinue
            }
        }
        
        if (-not $passwordsMatch) {
            Write-Host
            Write-Host "Failed to set password after 3 attempts. Exiting Script." -ForegroundColor Red
            exit 0
        }
    }
    else {
        # For decryption, implement retry logic with actual decryption attempts
        $attemptCount = 0
        $maxAttempts = 3
        $decryptionSuccess = $false
        
        while ($attemptCount -lt $maxAttempts -and -not $decryptionSuccess) {
            $attemptCount++
            Write-Host "Attempt $attemptCount of $maxAttempts" -ForegroundColor Yellow
            $securePassword = Read-Host -Prompt "Enter password" -AsSecureString
            
            # Check if password is empty/null
            if (-not $securePassword -or $securePassword.Length -eq 0) {
                Write-Host "Password cannot be empty. Please enter a valid password." -ForegroundColor Red
                continue
            }
            
            try {
                # Test the password by attempting decryption
                $testResult = Convert-SecureConfig -ConfigPath $ConfigPath -IsEncrypting $false -Password $securePassword
                
                if ($testResult) {
                    $Password = $securePassword
                    Write-Host "Password verified successfully!" -ForegroundColor Green
                    # Exit the loop since password is verified
                    break
                } else {
                    Write-Host "Incorrect password. Please try again." -ForegroundColor Red
                    if ($attemptCount -lt $maxAttempts) {
                        Write-Host "Remaining attempts: $($maxAttempts - $attemptCount)" -ForegroundColor Yellow
                    }
                }
            }
            catch {
                Write-Host "Incorrect password. Please try again." -ForegroundColor Red
                if ($attemptCount -lt $maxAttempts) {
                    Write-Host "Remaining attempts: $($maxAttempts - $attemptCount)" -ForegroundColor Yellow
                }
            }
            finally {
                # Clear the test password from memory
                if ($securePassword) {
                    $securePassword.Dispose()
                }
            }
        }
        
        if (-not $decryptionSuccess) {
            Write-Host 
            Write-Host "Failed to decrypt after $maxAttempts attempts. Exiting Script." -ForegroundColor Red
            exit 0
        }
    }
}

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
        # Initialize decryption success flag
        $decryptionSuccess = $false
        
        # Verify file exists
        if (-not (Test-Path $ConfigPath)) {
            throw "File not found: $ConfigPath"
        }

        # Get file content
        $configContent = Get-Content $ConfigPath -Raw

        # Generate output path (keep original extension)
        $outputPath = $ConfigPath

        if ($IsEncrypting) {
            # Check if already encrypted
            if (Test-EncryptedConfig -ConfigPath $ConfigPath) {
                throw "File is already encrypted. Decrypt it first if you want to re-encrypt."
            }

            # Generate unique random salt (32 bytes)
            $salt = New-Object byte[] 32
            $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
            try {
                $rng.GetBytes($salt)
            }
            finally {
                $rng.Dispose()
            }

            # Generate unique random IV (16 bytes) - SECURITY FIX
            $iv = New-Object byte[] 16
            $rng2 = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
            try {
                $rng2.GetBytes($iv)
            }
            finally {
                $rng2.Dispose()
            }

            # Convert SecureString to plaintext only when needed for crypto operations
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $plaintextPassword = $null
            try {
                $plaintextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                
                # Create key using PBKDF2 with higher iteration count - SECURITY FIX
                $rfc = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($plaintextPassword, $salt, 100000) # Increased from 1000 to 100000
                try {
                    $key = $rfc.GetBytes(32) # 256 bits

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
                        
                        # Create final encrypted package with salt and random IV
                        $package = @{
                            Salt = [Convert]::ToBase64String($salt)
                            Data = [Convert]::ToBase64String($encrypted)
                            IV = [Convert]::ToBase64String($iv)
                            Iterations = 100000  # Store iteration count for future compatibility
                            Algorithm = "AES-256-CBC"  # Document the algorithm used
                        } | ConvertTo-Json -Depth 5
                        
                        # Save encrypted content
                        $package | Set-Content $outputPath -Encoding UTF8
                        Write-Host "File encrypted successfully to: $outputPath" -ForegroundColor Green
                        Write-Host "Using AES-256-CBC with PBKDF2 (100,000 iterations)" -ForegroundColor Yellow
                        
                        # Return success for encryption
                        return $true
                    }
                    finally {
                        $aes.Dispose()
                        # Securely clear sensitive data from memory
                        for ($i = 0; $i -lt $key.Length; $i++) { $key[$i] = 0 }
                        for ($i = 0; $i -lt $iv.Length; $i++) { $iv[$i] = 0 }
                        for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = 0 }
                    }
                }
                finally {
                    $rfc.Dispose()
                    # Clear salt from memory
                    for ($i = 0; $i -lt $salt.Length; $i++) { $salt[$i] = 0 }
                }
            }
            finally {
                # Securely clear plaintext password from memory
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
                if ($plaintextPassword) { 
                    $plaintextPassword = "0" * $plaintextPassword.Length 
                    Remove-Variable -Name plaintextPassword -ErrorAction SilentlyContinue
                }
            }
        }
        else {
            try {
                Write-Host "Attempting to decrypt file..." -ForegroundColor Yellow
                
                # Parse the encrypted package
                $package = Get-Content $ConfigPath -Raw | ConvertFrom-Json
                
                if (-not $package.Salt -or -not $package.Data -or -not $package.IV) {
                    throw "Invalid encrypted file format. Required fields (Salt, Data, IV) are missing."
                }
                
                $salt = [Convert]::FromBase64String($package.Salt)
                $encrypted = [Convert]::FromBase64String($package.Data)
                $iv = [Convert]::FromBase64String($package.IV)

                # Use stored iteration count if available, otherwise default to new standard
                $iterations = if ($package.Iterations) { $package.Iterations } else { 100000 }
                
                # Convert SecureString to plaintext only when needed for crypto operations
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
                $plaintextPassword = $null
                try {
                    $plaintextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                    
                    # Recreate key from password and stored salt
                    $rfc = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($plaintextPassword, $salt, $iterations)
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
                            }
                            catch [System.Security.Cryptography.CryptographicException] {
                                throw "Decryption failed. This typically indicates an incorrect password."
                            }
                            catch {
                                throw "Decryption error: $($_.Exception.Message)"
                            }
                            finally {
                                $decryptor.Dispose()
                            }
                            
                            # Convert back to string
                            $decryptedText = [System.Text.Encoding]::UTF8.GetString($decrypted)
                            
                            # Validate decrypted content appears to be YAML
                            if ($decryptedText -match '^[\s]*[\w\-]+[\s]*:' -or $decryptedText -match '^[\s]*-[\s]+') {
                                Write-Host "Decrypted content appears to be valid YAML" -ForegroundColor Green
                            } else {
                                Write-Warning "Decrypted content may not be valid YAML format"
                            }
                            
                            # Save the decrypted content
                            $decryptedText | Set-Content $outputPath -Encoding UTF8
                            Write-Host "File decrypted successfully to: $outputPath" -ForegroundColor Green
                            
                            $decryptionSuccess = $true
                        }
                        finally {
                            $aes.Dispose()
                            # Securely clear sensitive data from memory
                            for ($i = 0; $i -lt $key.Length; $i++) { $key[$i] = 0 }
                            for ($i = 0; $i -lt $decrypted.Length; $i++) { $decrypted[$i] = 0 }
                        }
                    }
                    finally {
                        $rfc.Dispose()
                    }
                }
                finally {
                    # Securely clear plaintext password from memory
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
                    if ($plaintextPassword) { 
                        $plaintextPassword = "0" * $plaintextPassword.Length 
                        Remove-Variable -Name plaintextPassword -ErrorAction SilentlyContinue
                    }
                }
            }
            catch {
                # Always return false for wrong password, never exit
                $decryptionSuccess = $false
            }
        }
    }
    catch {
        # Always return false for errors, never exit
        $decryptionSuccess = $false
    }

    # Return true if decryption was successful (either for test or actual decryption)
    return $decryptionSuccess
}

# Execute based on parameter
try {
    if ($Encrypt) {
        $result = Convert-SecureConfig -ConfigPath $ConfigPath -IsEncrypting $true -Password $Password
        if (-not $result) {
            Write-Host "Encryption failed." -ForegroundColor Red
            exit 0
        }
    }
    else {
        # For decryption, we need to call Convert-SecureConfig
        if ($Password) {
            $result = Convert-SecureConfig -ConfigPath $ConfigPath -IsEncrypting $false -Password $Password
            if (-not $result) {
                Write-Host "Decryption failed." -ForegroundColor Red
                exit 0
            }
        } else {
            Write-Host "No password provided for decryption." -ForegroundColor Red
            exit 0
        }
    }
}
finally {
    # Clear SecureString password from memory
    if ($Password) {
        $Password.Dispose()
        Remove-Variable -Name Password -ErrorAction SilentlyContinue
    }
}