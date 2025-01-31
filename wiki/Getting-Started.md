# Getting Started with WinforgeX

WinforgeX is designed to be run remotely, allowing organizations to maintain centralized configurations while enabling easy deployment across multiple machines.

## Prerequisites

- Windows PowerShell 5.1 or later
- Administrator privileges
- Internet connection
- PSToml module (automatically installed)

## Execution Methods

### 1. Remote Execution (Recommended)

Run WinforgeX directly from GitHub with your configuration:

```powershell
# Basic remote execution
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Graphixa/WinforgeX/main/winforge.ps1))) -config "https://raw.githubusercontent.com/yourdomain/config.toml"

# With custom log path
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Graphixa/WinforgeX/main/winforge.ps1))) -config "https://raw.githubusercontent.com/yourdomain/config.toml" -LogPath "C:\CustomLogs\winforge.log"
```

#### Benefits of Remote Execution
- No local script installation required
- Always runs the latest version
- Centralized configuration management
- Easy to distribute and update
- Consistent deployment across machines

### 2. Local Execution

If you prefer to run WinforgeX locally:

1. Clone or download the repository:
```powershell
git clone https://github.com/Graphixa/WinforgeX.git
cd WinforgeX
```

2. Run the script:
```powershell
.\winforge.ps1 -config="path\to\config.toml"
```

## Configuration Options

### 1. Remote Configuration (Recommended)
Host your configuration file in a centralized location:
- GitHub repository
- Internal web server
- Network share

Example structure:
```
company-configs/
├── departments/
│   ├── it.toml
│   ├── finance.toml
│   └── hr.toml
├── roles/
│   ├── developer.toml
│   ├── admin.toml
│   └── user.toml
└── base.toml
```

### 2. Local Configuration
Store configuration files locally:
```
C:\Configs\
├── config.toml
└── encrypted-config.toml
```

## Basic Configuration Example

```toml
[System]
DisableUAC = true
DisableWindowsDefender = false

[Applications]
PackageManager = "winget"
Install = ["7zip", "firefox", "vscode", "nodejs"]
Uninstall = ["7zip", "MSEdge"]

[Network.Drives]
MapDrives = [
    { Letter = "X", Path = "\\\\server\\share", Username = "domain\\user", Password = "encrypted" }
]
```

## Logging

By default, WinforgeX logs to `C:\Winforge.log`, but you can specify your own custom log path:

```powershell
# Remote execution with custom log path
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Graphixa/WinforgeX/main/winforge.ps1))) -config "https://config.url/config.toml" -LogPath "C:\Logs\winforge.log"

# Local execution with custom log path
.\winforge.ps1 -config="config.toml" -LogPath "C:\Logs\winforge.log"
```

## Security Considerations

1. **Configuration Source**
   - Use HTTPS for remote configurations
   - Validate configuration source URLs
   - Consider using private repositories

2. **Credentials**
   - Use encrypted configurations for sensitive data
   - Store credentials securely
   - Use environment variables where possible

3. **Execution**
   - Run as administrator
   - Use execution policy management
   - Review logs for unauthorized changes

## Next Steps

1. Review the [TOML Configuration Guide](TOML-Configuration-Guide)
2. Check [Examples](Examples) for common scenarios
3. Learn about [Security Settings](Security-Settings)
4. Understand [Troubleshooting](Troubleshooting) procedures

## Common Issues

1. **Permission Denied**
   ```powershell
   # Run PowerShell as Administrator
   Start-Process powershell -Verb RunAs
   ```

2. **Module Not Found**
   ```powershell
   # Install PSToml manually
   Install-Module -Name PSToml -Force -Scope CurrentUser
   ```

3. **Configuration Not Found**
   - Verify URL/path is correct
   - Check network path/url is correct
   - Validate file permissions

4. **Execution Policy**
   ```powershell
   # Set execution policy
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```

## Support

If you encounter issues:
1. Check the log file
2. Review [Troubleshooting](Troubleshooting)
3. Submit an issue on GitHub