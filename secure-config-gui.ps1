Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Helper Functions
function Add-RoundedCorners {
    param(
        [System.Windows.Forms.Control]$Control,
        [int]$Radius = 10
    )
    
    $Control.Paint += {
        $rect = New-Object System.Drawing.Rectangle(0, 0, $this.Width, $this.Height)
        $path = New-Object System.Drawing.Drawing2D.GraphicsPath
        $path.AddArc($rect.X, $rect.Y, $Radius*2, $Radius*2, 180, 90)
        $path.AddArc($rect.Right - $Radius*2, $rect.Y, $Radius*2, $Radius*2, 270, 90)
        $path.AddArc($rect.Right - $Radius*2, $rect.Bottom - $Radius*2, $Radius*2, $Radius*2, 0, 90)
        $path.AddArc($rect.X, $rect.Bottom - $Radius*2, $Radius*2, $Radius*2, 90, 90)
        $this.Region = New-Object System.Drawing.Region($path)
    }
}

function Update-ButtonState {
    param([bool]$IsEncrypted)
    
    if ($IsEncrypted) {
        $script:actionButton.Text = 'Decrypt'
        $script:actionButton.BackColor = [System.Drawing.Color]::FromArgb(220, 38, 38)  # #dc2626
        $script:actionButton.Tag = 'decrypt'
    } else {
        $script:actionButton.Text = 'Encrypt'
        $script:actionButton.BackColor = [System.Drawing.Color]::FromArgb(0, 162, 15)  # #00a20f
        $script:actionButton.Tag = 'encrypt'
    }
    $script:actionButton.Enabled = $true
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
        [string]$FilePath,
        [bool]$IsEncrypting,
        [string]$Password
    )
    
    try {
        $outputPath = $FilePath
        if ($IsEncrypting) {
            # Generate random salt
            $salt = New-Object byte[] 32
            $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
            $rng.GetBytes($salt)
            
            # Create key from password and salt
            $rfc = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 1000)
            try {
                $key = $rfc.GetBytes(32)
                
                # Create AES encryption object
                $aes = [System.Security.Cryptography.Aes]::Create()
                try {
                    $aes.Key = $key
                    $aes.GenerateIV()
                    $iv = $aes.IV
                    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                    
                    # Get file content and encrypt
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes((Get-Content $FilePath -Raw))
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
                    return $true
                }
                finally {
                    $aes.Dispose()
                }
            }
            finally {
                $rfc.Dispose()
            }
        }
        else {
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

                    # Decrypt
                    $decryptor = $aes.CreateDecryptor()
                    try {
                        $decrypted = $decryptor.TransformFinalBlock($encrypted, 0, $encrypted.Length)
                    }
                    finally {
                        $decryptor.Dispose()
                    }
                    
                    # Convert back to string and save
                    $decryptedText = [System.Text.Encoding]::UTF8.GetString($decrypted)
                    $decryptedText | Set-Content $outputPath -Encoding UTF8
                    return $true
                }
                finally {
                    $aes.Dispose()
                }
            }
            finally {
                $rfc.Dispose()
            }
        }
    }
    catch {
        throw
    }
}

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Winforge Config Encryptor'
$form.Size = New-Object System.Drawing.Size(600,400)
$form.StartPosition = 'CenterScreen'
$form.BackColor = [System.Drawing.Color]::FromArgb(31, 41, 55)  # #1f2937
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox = $false

# Create title label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Location = New-Object System.Drawing.Point(0,20)
$titleLabel.Size = New-Object System.Drawing.Size(600,30)
$titleLabel.Text = "WINFORGE CONFIGURATION ENCRYPTOR"
$titleLabel.ForeColor = [System.Drawing.Color]::White
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$titleLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter

# Create file panel
$filePanel = New-Object System.Windows.Forms.Panel
$filePanel.Size = New-Object System.Drawing.Size(500,70)
$filePanel.Location = New-Object System.Drawing.Point(50,80)
$filePanel.BackColor = [System.Drawing.Color]::FromArgb(17, 24, 39)  # #111827

# Create file path container and label
$textBoxContainer = New-Object System.Windows.Forms.Panel
$textBoxContainer.Size = New-Object System.Drawing.Size(350,40)
$textBoxContainer.Location = New-Object System.Drawing.Point(20,15)
$textBoxContainer.BackColor = [System.Drawing.Color]::FromArgb(17, 24, 39)
Add-RoundedCorners -Control $textBoxContainer

$filePathBox = New-Object System.Windows.Forms.Label
$filePathBox.Location = New-Object System.Drawing.Point(10,10)
$filePathBox.Size = New-Object System.Drawing.Size(330,20)
$filePathBox.BackColor = [System.Drawing.Color]::FromArgb(17, 24, 39)
$filePathBox.ForeColor = [System.Drawing.Color]::White
$filePathBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$filePathBox.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft

# Create select button
$selectButton = New-Object System.Windows.Forms.Button
$selectButton.Location = New-Object System.Drawing.Point(390,15)
$selectButton.Size = New-Object System.Drawing.Size(90,40)
$selectButton.Text = 'Select File'
$selectButton.BackColor = [System.Drawing.Color]::FromArgb(0, 131, 223)  # #0083df
$selectButton.ForeColor = [System.Drawing.Color]::White
$selectButton.FlatStyle = 'Flat'
$selectButton.FlatAppearance.BorderSize = 0
$selectButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
Add-RoundedCorners -Control $selectButton

# Create button panel
$buttonPanel = New-Object System.Windows.Forms.Panel
$buttonPanel.Size = New-Object System.Drawing.Size(500,70)
$buttonPanel.Location = New-Object System.Drawing.Point(50,170)
$buttonPanel.BackColor = [System.Drawing.Color]::FromArgb(17, 24, 39)  # #111827

# Create action button
$script:actionButton = New-Object System.Windows.Forms.Button
$script:actionButton.Size = New-Object System.Drawing.Size(460,40)
$script:actionButton.Location = New-Object System.Drawing.Point(20,15)
$script:actionButton.Text = 'Encrypt'
$script:actionButton.BackColor = [System.Drawing.Color]::FromArgb(0, 162, 15)  # #00a20f
$script:actionButton.ForeColor = [System.Drawing.Color]::White
$script:actionButton.FlatStyle = 'Flat'
$script:actionButton.FlatAppearance.BorderSize = 0
$script:actionButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:actionButton.Tag = 'encrypt'
$script:actionButton.Enabled = $false
Add-RoundedCorners -Control $script:actionButton

# Create status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point(50,260)
$statusLabel.Size = New-Object System.Drawing.Size(500,30)
$statusLabel.Text = 'Ready'
$statusLabel.ForeColor = [System.Drawing.Color]::White
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter

# Add controls to containers
$textBoxContainer.Controls.Add($filePathBox)
$filePanel.Controls.AddRange(@($textBoxContainer, $selectButton))
$buttonPanel.Controls.Add($script:actionButton)

# Add all panels to form
$form.Controls.AddRange(@(
    $titleLabel,
    $filePanel,
    $buttonPanel,
    $statusLabel
))

# Add event handlers
$selectButton.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Configuration files (*.xml;*.config)|*.xml;*.config|All files (*.*)|*.*"
    if ($openFileDialog.ShowDialog() -eq 'OK') {
        $script:selectedFile = $openFileDialog.FileName
        $filePathBox.Text = $script:selectedFile
        $script:isEncrypted = Test-EncryptedConfig -FilePath $script:selectedFile
        Update-ButtonState -IsEncrypted $script:isEncrypted
        $statusLabel.Text = "File loaded: " + $(if ($script:isEncrypted) { "Encrypted" } else { "Not encrypted" })
    }
})

# Add the action button click handler
$script:actionButton.Add_Click({
    if ($actionButton.Tag -eq 'encrypt') {
        $passwordForm = New-Object System.Windows.Forms.Form
        $passwordForm.Text = "Enter Password"
        $passwordForm.Size = New-Object System.Drawing.Size(300,200)
        $passwordForm.StartPosition = 'CenterParent'
        $passwordForm.BackColor = [System.Drawing.Color]::FromArgb(31, 41, 55)
        $passwordForm.FormBorderStyle = 'FixedDialog'
        $passwordForm.MaximizeBox = $false
        $passwordForm.MinimizeBox = $false

        $password1 = New-Object System.Windows.Forms.MaskedTextBox
        $password1.PasswordChar = '●'
        $password1.Location = New-Object System.Drawing.Point(20,30)
        $password1.Size = New-Object System.Drawing.Size(240,20)
        $password1.BackColor = [System.Drawing.Color]::FromArgb(17, 24, 39)
        $password1.ForeColor = [System.Drawing.Color]::White

        $password2 = New-Object System.Windows.Forms.MaskedTextBox
        $password2.PasswordChar = '●'
        $password2.Location = New-Object System.Drawing.Point(20,80)
        $password2.Size = New-Object System.Drawing.Size(240,20)
        $password2.BackColor = [System.Drawing.Color]::FromArgb(17, 24, 39)
        $password2.ForeColor = [System.Drawing.Color]::White

        $label1 = New-Object System.Windows.Forms.Label
        $label1.Location = New-Object System.Drawing.Point(20,10)
        $label1.Size = New-Object System.Drawing.Size(240,20)
        $label1.Text = 'Enter password:'
        $label1.ForeColor = [System.Drawing.Color]::White
        $label1.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

        $label2 = New-Object System.Windows.Forms.Label
        $label2.Location = New-Object System.Drawing.Point(20,60)
        $label2.Size = New-Object System.Drawing.Size(240,20)
        $label2.Text = 'Confirm password:'
        $label2.ForeColor = [System.Drawing.Color]::White
        $label2.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(60,120)
        $okButton.Size = New-Object System.Drawing.Size(75,23)
        $okButton.Text = 'OK'
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $okButton.BackColor = [System.Drawing.Color]::FromArgb(0, 131, 223)
        $okButton.ForeColor = [System.Drawing.Color]::White
        $okButton.FlatStyle = 'Flat'
        $okButton.FlatAppearance.BorderSize = 0

        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(150,120)
        $cancelButton.Size = New-Object System.Drawing.Size(75,23)
        $cancelButton.Text = 'Cancel'
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $cancelButton.BackColor = [System.Drawing.Color]::FromArgb(220, 38, 38)
        $cancelButton.ForeColor = [System.Drawing.Color]::White
        $cancelButton.FlatStyle = 'Flat'
        $cancelButton.FlatAppearance.BorderSize = 0

        $passwordForm.Controls.AddRange(@($password1, $password2, $label1, $label2, $okButton, $cancelButton))
        $passwordForm.AcceptButton = $okButton
        $passwordForm.CancelButton = $cancelButton

        $result = $passwordForm.ShowDialog()
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            # Check for empty or too short passwords
            if ([string]::IsNullOrWhiteSpace($password1.Text) -or $password1.Text.Length -lt 6) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Password must be at least 6 characters long.",
                    "Invalid Password",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                return
            }

            if ($password1.Text -eq $password2.Text) {
                try {
                    $statusLabel.Text = "Encrypting..."
                    $form.Refresh()
                    
                    if (Convert-SecureConfig -FilePath $script:selectedFile -IsEncrypting $true -Password $password1.Text) {
                        $statusLabel.Text = "File encrypted successfully!"
                        $script:isEncrypted = $true
                        Update-ButtonState -IsEncrypted $true
                    }
                }
                catch {
                    [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                    $statusLabel.Text = "Encryption failed!"
                }
            }
            else {
                [System.Windows.Forms.MessageBox]::Show("Passwords do not match!", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    } else {
        $passwordForm = New-Object System.Windows.Forms.Form
        $passwordForm.Text = "Enter Password"
        $passwordForm.Size = New-Object System.Drawing.Size(300,150)
        $passwordForm.StartPosition = 'CenterParent'
        $passwordForm.BackColor = [System.Drawing.Color]::FromArgb(31, 41, 55)
        $passwordForm.FormBorderStyle = 'FixedDialog'
        $passwordForm.MaximizeBox = $false
        $passwordForm.MinimizeBox = $false

        $password = New-Object System.Windows.Forms.MaskedTextBox
        $password.PasswordChar = '●'
        $password.Location = New-Object System.Drawing.Point(20,30)
        $password.Size = New-Object System.Drawing.Size(240,20)
        $password.BackColor = [System.Drawing.Color]::FromArgb(17, 24, 39)
        $password.ForeColor = [System.Drawing.Color]::White

        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(20,10)
        $label.Size = New-Object System.Drawing.Size(240,20)
        $label.Text = 'Enter password:'
        $label.ForeColor = [System.Drawing.Color]::White
        $label.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(60,70)
        $okButton.Size = New-Object System.Drawing.Size(75,23)
        $okButton.Text = 'OK'
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $okButton.BackColor = [System.Drawing.Color]::FromArgb(0, 131, 223)
        $okButton.ForeColor = [System.Drawing.Color]::White
        $okButton.FlatStyle = 'Flat'
        $okButton.FlatAppearance.BorderSize = 0

        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(150,70)
        $cancelButton.Size = New-Object System.Drawing.Size(75,23)
        $cancelButton.Text = 'Cancel'
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $cancelButton.BackColor = [System.Drawing.Color]::FromArgb(220, 38, 38)
        $cancelButton.ForeColor = [System.Drawing.Color]::White
        $cancelButton.FlatStyle = 'Flat'
        $cancelButton.FlatAppearance.BorderSize = 0

        $passwordForm.Controls.AddRange(@($password, $label, $okButton, $cancelButton))
        $passwordForm.AcceptButton = $okButton
        $passwordForm.CancelButton = $cancelButton

        $result = $passwordForm.ShowDialog()
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $statusLabel.Text = "Decrypting..."
                $form.Refresh()
                
                if (Convert-SecureConfig -FilePath $script:selectedFile -IsEncrypting $false -Password $password.Text) {
                    $statusLabel.Text = "File decrypted successfully!"
                    $script:isEncrypted = $false
                    Update-ButtonState -IsEncrypted $false
                }
            }
            catch {
                # Check if it's a decryption error (usually means wrong password)
                if ($_.Exception.Message -match "Padding is invalid|Bad Data|Length of the data to decrypt is invalid") {
                    [System.Windows.Forms.MessageBox]::Show(
                        "The password you entered is incorrect. Please try again.",
                        "Incorrect Password",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Warning
                    )
                } else {
                    # For other types of errors, show the actual error message
                    [System.Windows.Forms.MessageBox]::Show(
                        $_.Exception.Message,
                        "Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                }
                $statusLabel.Text = "Decryption failed!"
            }
        }
    }
})

# Show the form
$form.ShowDialog()