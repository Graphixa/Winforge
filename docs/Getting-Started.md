# Getting Started with Winforge

This guide will help you get up and running with Winforge quickly and efficiently. Whether you're configuring a single machine or managing multiple deployments, these instructions will get you started.

## Prerequisites

Before you begin, ensure you have:

1. **Windows System**
   - Windows 11 (Windows 10 has not been tested)
   - PowerShell 5.1 or later
   - Administrator privileges

2. **Optional Tools**
   - Git (for cloning the repository)
   - A text editor for TOML files (VS Code recommended)

## Quick Setup

### Method 1: Direct Remote Execution (Recommended)

The fastest way to get started is running Winforge directly from GitHub:

```powershell
# Run as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Graphixa/Winforge/main/winforge.ps1))) -config "https://raw.githubusercontent.com/yourdomain/config.toml"
```

### Method 2: Local Installation

1. **Download Winforge**:
   ```powershell
   # Clone the repository
   git clone https://github.com/Graphixa/Winforge.git
   cd Winforge
   ```

2. **Run Locally**:
   ```powershell
   # Run as Administrator
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\winforge.ps1 -config="path\to\config.toml"
   ```

## Creating Your First Configuration

1. **Start with a Template**
   - Copy the example configuration:
     ```toml
     # config.toml
     [System]
     ComputerName = "MyPC"
     Timezone = "UTC"
     
     [Applications]
     PackageManager = "winget"
     Install = [
         "Microsoft.VisualStudioCode",
         "Mozilla.Firefox"
     ]
     
     [Theme]
     DarkMode = true
     
     [Privacy]
     DisableTelemetry = true
     ```

2. **Customize Your Config**
   - Modify settings according to your needs
   - See the [TOML Configuration Guide](TOML-Configuration-Guide) for all options
   - Use environment-specific sections as needed

## Common Configurations

### Developer Setup
```toml
[Applications]
PackageManager = "winget"
Install = [
    "Microsoft.VisualStudioCode",
    "Git.Git",
    "Docker.DockerDesktop",
    "Microsoft.PowerShell"
]

[EnvironmentVariables]
User = [
    {VariableName = "Path", Value = "%USERPROFILE%\\.local\\bin"},
    {VariableName = "Path", Value = "%USERPROFILE%\\AppData\\Local\\Programs\\Python\\Python310\\Scripts"}
]
```

### Home User Setup
```toml
[Applications]
PackageManager = "winget"
Install = [
    "Mozilla.Firefox",
    "VideoLAN.VLC",
    "7zip.7zip"
]

[Theme]
DarkMode = true
DesktopIconSize = "medium"

[Power]
PowerPlan = "Balanced"
AllowSleep = true

[Privacy]
DisableTelemetry = true
```

### Work Environment
```toml
[Applications]
PackageManager = "winget"
Install = [
    "Microsoft.Office",
    "Microsoft.Teams",
    "Zoom.Zoom"
]

[Network]
MapDrive = [
    { Letter = "S", Path = "\\\\server\\share", Persistent = true }
]

[Privacy]
DisableTelemetry = true
```

## Running Winforge

### Running Configuration Files

1. **Remote Configuration**:
   ```powershell
   .\winforge.ps1 -config="https://raw.githubusercontent.com/yourdomain/config.toml"
   ```

2. **Local Configuration**:
   ```powershell
   .\winforge.ps1 -config="C:\path\to\config.toml"
   ```

3. **With Logging**:
   ```powershell
   .\winforge.ps1 -config="config.toml" -logPath "C:\path\to\log-output.txt"
   ```

## Monitoring Progress

1. **Check Logs**
   - Default log location: `%SYSTEMROOT%\winforge.log`
   - Review for errors or warnings

2. **Console Output**
   - Watch real-time progress
   - Error messages are in red
   - Warnings in yellow
   - Success messages in green

## Next Steps

1. Review the [TOML Configuration Guide](TOML-Configuration-Guide) for all available options
2. Check out example configurations in the [Examples](Examples) section
3. Join the community:
   - Star the GitHub repository
   - Report issues or suggest features
   - Feel free to share your configuration templates but be careful not share any sensitive information like passwords, keys, etc.

## Troubleshooting

If you encounter issues:

1. **Check Requirements**
   - Verify PowerShell version: `$PSVersionTable.PSVersion`
   - Confirm you are running as Administrator
   - Make sure you're connected to the internet

2. **Common Issues**
   - Execution Policy: Run `Set-ExecutionPolicy Bypass -Scope Process`
   - File Access: Ensure config file is accessible
   - Network: Check proxy settings if behind corporate firewall

3. **Getting Help**
   - See [Troubleshooting Guide](Troubleshooting) for detailed solutions
   - Search [existing issues](https://github.com/Graphixa/Winforge/issues)
   - Submit a [new issue](https://github.com/Graphixa/Winforge/issues/new)

## Security Notes

- Always review configuration files before execution
- Use secure sources for remote configurations
- Keep your PowerShell and Windows up to date
- Follow your organization's security policies