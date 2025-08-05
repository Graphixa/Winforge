<#
.SYNOPSIS
    Winforge Interactive GUI Launcher
.DESCRIPTION
    Windows Forms GUI launcher for Winforge operations.
    Provides an interactive menu for running Winforge, encrypting, and decrypting configuration files.

.NOTES
    Requires Windows Forms support (Windows only)
    Uses PSMenu module for interactive menus
#>

# Add Windows Forms support
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Import PSMenu module if available
if (Get-Module -ListAvailable -Name PSMenu) {
    Import-Module PSMenu
} else {
    Write-Warning "PSMenu module not found. Installing..."
    Install-Module -Name PSMenu -Scope CurrentUser -Force
    Import-Module PSMenu
}

# GitHub repository URLs
$script:WinforgeUrl = "https://raw.githubusercontent.com/Graphixa/Winforge/refs/heads/main/winforge.ps1"
$script:EncryptionUrl = "https://raw.githubusercontent.com/Graphixa/Winforge/refs/heads/main/encryption-utility.ps1"

function Show-FilePicker {
    param(
        [string]$Title = "Select Configuration File",
        [string]$Filter = "YAML files (*.yaml;*.yml)|*.yaml;*.yml|All files (*.*)|*.*"
    )
    
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = $Filter
    $openFileDialog.Title = $Title
    $openFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    
    if ($openFileDialog.ShowDialog() -eq 'OK') {
        return $openFileDialog.FileName
    }
    return $null
}

function Invoke-WinforgeScript {
    param(
        [string]$ScriptUrl,
        [string]$Parameters = ""
    )
    
    try {
        Write-Host "Downloading and executing script..." -ForegroundColor Cyan
        
        if ($Parameters) {
            # Execute with parameters - use exact same pattern as working command
            $command = "& ([scriptblock]::Create((irm '$ScriptUrl'))) $Parameters"
            Write-Host "Executing: $command" -ForegroundColor Gray
            Invoke-Expression $command
        } else {
            # Execute without parameters (will prompt interactively)
            $command = "& ([scriptblock]::Create((irm '$ScriptUrl')))"
            Write-Host "Executing: $command" -ForegroundColor Gray
            Invoke-Expression $command
        }
        
        Write-Host "Script execution completed." -ForegroundColor Green
    }
    catch {
        Write-Error "Error executing script: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show(
            "Error executing script: $($_.Exception.Message)",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}

function Show-MainMenu {
    Clear-Host
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    WINFORGE INTERACTIVE                     ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║                                                              ║" -ForegroundColor Cyan
    Write-Host "║  Select an operation:                                       ║" -ForegroundColor Cyan
    Write-Host "║                                                              ║" -ForegroundColor Cyan
    Write-Host "║  1. Run Winforge (with file picker)                        ║" -ForegroundColor White
    Write-Host "║  2. Encrypt Configuration File                              ║" -ForegroundColor White
    Write-Host "║  3. Decrypt Configuration File                              ║" -ForegroundColor White
    Write-Host "║  4. Exit                                                    ║" -ForegroundColor White
    Write-Host "║                                                              ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Handle-RunWinforge {
    Write-Host "Opening file picker for configuration file..." -ForegroundColor Yellow
    
    $configFile = Show-FilePicker -Title "Select Winforge Configuration File"
    
    if ($configFile) {
        Write-Host "Selected file: $configFile" -ForegroundColor Green
        Write-Host "Executing Winforge..." -ForegroundColor Cyan
        
        # Execute winforge with the selected file
        Invoke-WinforgeScript -ScriptUrl $script:WinforgeUrl -Parameters "-ConfigPath `"$configFile`""
    } else {
        Write-Host "No file selected. Operation cancelled." -ForegroundColor Yellow
    }
}

function Handle-EncryptFile {
    Write-Host "Opening file picker for file to encrypt..." -ForegroundColor Yellow
    
    $configFile = Show-FilePicker -Title "Select File to Encrypt"
    
    if ($configFile) {
        Write-Host "Selected file: $configFile" -ForegroundColor Green
        Write-Host "Executing encryption..." -ForegroundColor Cyan
        
        # Execute encryption utility with the selected file
        Invoke-WinforgeScript -ScriptUrl $script:EncryptionUrl -Parameters "-ConfigPath `"$configFile`" -Encrypt"
    } else {
        Write-Host "No file selected. Operation cancelled." -ForegroundColor Yellow
    }
}

function Handle-DecryptFile {
    Write-Host "Opening file picker for file to decrypt..." -ForegroundColor Yellow
    
    $configFile = Show-FilePicker -Title "Select File to Decrypt"
    
    if ($configFile) {
        Write-Host "Selected file: $configFile" -ForegroundColor Green
        Write-Host "Executing decryption..." -ForegroundColor Cyan
        
        # Execute encryption utility with the selected file
        Invoke-WinforgeScript -ScriptUrl $script:EncryptionUrl -Parameters "-ConfigPath `"$configFile`" -Decrypt"
    } else {
        Write-Host "No file selected. Operation cancelled." -ForegroundColor Yellow
    }
}

# Main execution
try {
    Write-Host "Welcome to Winforge Interactive!" -ForegroundColor Green
    Write-Host "This tool provides a GUI interface for Winforge operations." -ForegroundColor Gray
    Write-Host ""
    
    do {
        Show-MainMenu
        
        $choice = Read-Host "Enter your choice (1-4)"
        
        switch ($choice) {
            "1" {
                Handle-RunWinforge
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "2" {
                Handle-EncryptFile
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "3" {
                Handle-DecryptFile
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "4" {
                Write-Host "Exiting Winforge Interactive. Goodbye!" -ForegroundColor Green
                exit 0
            }
            default {
                Write-Host "Invalid choice. Please enter 1-4." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($true)
}
catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    Read-Host "Press Enter to exit"
    exit 1
} 