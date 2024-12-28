[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $true, ParameterSetName = "Encrypt")]
    [switch]$Encrypt,

    [Parameter(Mandatory = $true, ParameterSetName = "Decrypt")] 
    [switch]$Decrypt,

    [Parameter(Mandatory = $false)]
    [string]$Password
)

function Test-EncryptedConfig {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        # Try to parse the content as JSON
        $content = Get-Content $FilePath -Raw
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

# First check if file exists
if (-not (Test-Path $FilePath)) {
    Write-Error "File not found: $FilePath"
    exit 1
}

# Check encryption status based on operation
if ($Decrypt) {
    $isEncrypted = Test-EncryptedConfig -FilePath $FilePath
    if (-not $isEncrypted) {
        Write-Host "File is not encrypted. Skipping decryption."
        exit 0
    }
}
elseif ($Encrypt) {
    $isEncrypted = Test-EncryptedConfig -FilePath $FilePath
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
        while (-not $passwordsMatch) {
            $securePassword1 = Read-Host -Prompt "Enter password" -AsSecureString
            $securePassword2 = Read-Host -Prompt "Re-enter password" -AsSecureString
            
            $BSTR1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword1)
            $BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword2)
            
            try {
                $pass1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR1)
                $pass2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)
                
                if ($pass1 -eq $pass2) {
                    $Password = $pass1
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
    }
    else {
        # For decryption, just ask once
        $securePassword = Read-Host -Prompt "Enter password" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        try {
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
    }
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
            $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
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
                    
                    # Create final encrypted package with salt
                    $package = @{
                        Salt = [Convert]::ToBase64String($salt)
                        Data = [Convert]::ToBase64String($encrypted)
                        IV = [Convert]::ToBase64String($iv)
                    } | ConvertTo-Json
                    
                    # Save encrypted content
                    $package | Set-Content $outputPath
                    Write-Host "File encrypted successfully to: $outputPath"
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
                $package = Get-Content $FilePath -Raw | ConvertFrom-Json
                $salt = [Convert]::FromBase64String($package.Salt)
                $encrypted = [Convert]::FromBase64String($package.Data)
                $iv = [Convert]::FromBase64String($package.IV)

                # Recreate key from password and stored salt
                $rfc = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 1000)
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
                Write-Error $_.Exception.Message
                exit 1
            }
        }
    }
    catch {
        Write-Error "Error processing file: $($_.Exception.Message)"
        exit 1
    }
}

# Execute based on parameter
try {
    if ($Encrypt) {
        Convert-SecureConfig -FilePath $FilePath -IsEncrypting $true -Password $Password
    }
    else {
        Convert-SecureConfig -FilePath $FilePath -IsEncrypting $false -Password $Password
    }
}
finally {
    # Clear password from memory
    if ($Password) {
        $Password = "0" * $Password.Length
        Remove-Variable -Name Password
    }
}