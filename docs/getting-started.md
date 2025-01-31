# Getting Started with WinforgeX

This guide will help you get started with WinforgeX, from installation to your first configuration deployment.

## Requirements

- Windows PowerShell 5.1 or later
- Administrator privileges
- PSToml module (automatically installed if missing)
- Internet connection (for package management features)

## Installation

1. Clone or download the WinforgeX repository:
```powershell
git clone https://github.com/yourusername/WinforgeX.git
cd WinforgeX
```

2. Install required PowerShell module:
```powershell
Install-Module -Name PSToml -Force -Scope CurrentUser
```

3. (Optional) If you plan to use package management features:
```powershell
# Install Winget (Windows Package Manager)
# Usually pre-installed on Windows 10/11

# Install Chocolatey (Optional)
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

## Basic Usage

1. Create a basic configuration file (config.toml):
```toml
[System]
DisableUAC = true
DisableWindowsDefender = false

[Applications.Install]
Apps = [
    { Name = "Microsoft.VisualStudioCode", Version = "latest" },
    { Name = "Google.Chrome", Version = "stable" }
]
```

2. Run WinforgeX:
```powershell
.\winforge.ps1 -ConfigPath "config.toml"
```

3. Check the log file (default: C:\Winforge.log) for execution details.

## Configuration Structure

Your TOML configuration file can include these main sections:

- `System`: System-wide settings
- `Applications`: Software installation/removal
- `Network`: Network drive mapping and settings
- `Security`: Security and BitLocker settings
- `FileOperations`: File and shortcut operations
- `Registry`: Registry modifications
- `Office`: Microsoft Office configuration
- `Power`: Power management settings
- `Privacy`: Privacy and telemetry settings
- `Commands`: Custom command execution

## Example Configuration

Here's a more comprehensive example:

```toml
[System]
DisableUAC = true
DisableWindowsDefender = false
DisableRemoteDesktop = false

[Applications]
PackageManager = "winget"

[Applications.Install]
Apps = [
    { Name = "Microsoft.VisualStudioCode", Version = "latest" },
    { Name = "Google.Chrome", Version = "stable" }
]

[Network.Drives]
MapDrives = [
    { Letter = "X", Path = "\\\\server\\share", Username = "domain\\user", Password = "encrypted" }
]

[FileOperations.Shortcuts]
Create = [
    { Name = "Chrome", Target = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", Location = "Desktop" }
]
```

## Next Steps

- Read the [Configuration Guide](configuration-guide.md) for detailed TOML syntax
- Check [Examples](examples/README.md) for common scenarios
- Review [Feature Documentation](features/README.md) for detailed feature information
- See [Troubleshooting](troubleshooting.md) if you encounter issues

## Common Issues

1. **Permission Denied**: Run PowerShell as Administrator
2. **Module Not Found**: Install PSToml module manually
3. **Configuration Error**: Validate TOML syntax using online tools
4. **Package Installation Failed**: Check internet connection and package name

## Support

For additional help:
1. Check the documentation
2. Review the troubleshooting guide
3. Submit an issue on our repository
4. Contact the development team 