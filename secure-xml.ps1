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

# If password not provided, prompt securely
if (-not $Password) {
    $securePassword = Read-Host -Prompt "Enter password" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    try {
        $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}

function Convert-SecureXml {
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
        $xmlContent = Get-Content $FilePath -Raw

        # Generate output path
        $outputPath = [System.IO.Path]::ChangeExtension($FilePath, ".config")

        if ($IsEncrypting) {
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
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($xmlContent)

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
        Convert-SecureXml -FilePath $FilePath -IsEncrypting $true -Password $Password
    }
    else {
        Convert-SecureXml -FilePath $FilePath -IsEncrypting $false -Password $Password
    }
}
finally {
    # Clear password from memory
    if ($Password) {
        $Password = "0" * $Password.Length
        Remove-Variable -Name Password
    }
}