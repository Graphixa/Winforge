# WinforgeX Configuration Guide

This guide provides detailed information about the TOML configuration format used by WinforgeX.

## TOML Format Overview

TOML (Tom's Obvious, Minimal Language) is a simple configuration file format that's easy to read and write. WinforgeX uses TOML for its configuration files.

### Basic Syntax

```toml
# This is a comment

# Simple key-value pairs
key = "value"
boolean = true
number = 42

# Arrays
array = [ 1, 2, 3 ]

# Tables (sections)
[section]
key = "value"

# Array of tables
[[array_of_tables]]
name = "first"
[[array_of_tables]]
name = "second"
```

## Configuration Sections

### System Configuration
```toml
[System]
DisableUAC = true                  # Disable User Account Control
DisableWindowsDefender = false     # Keep Windows Defender enabled
DisableRemoteDesktop = false       # Enable Remote Desktop
DisableFirewall = false            # Keep Windows Firewall enabled
DisableSystemRestore = true        # Disable System Restore
DisableWindowsUpdate = false       # Keep Windows Update enabled
SetupDevicePrompt = true          # Show device setup prompt
```

### Application Management
```toml
[Applications]
PackageManager = "winget"          # Use winget as package manager

[Applications.Install]
Apps = [
    { Name = "Microsoft.VisualStudioCode", Version = "latest" },
    { Name = "Google.Chrome", Version = "stable" }
]

[Applications.Remove]
Apps = [
    { Name = "Microsoft.BingNews" },
    { Name = "Microsoft.BingWeather" }
]
```

### Network Configuration
```toml
[Network.Drives]
MapDrives = [
    { 
        Letter = "X",
        Path = "\\\\server\\share",
        Username = "domain\\user",
        Password = "encrypted"
    }
]
```

### File Operations
```toml
[FileOperations.Copy]
Files = [
    { 
        Source = "%USERPROFILE%\\Documents\\file.txt",
        Destination = "%ProgramFiles%\\App\\file.txt"
    }
]

[FileOperations.Shortcuts]
Create = [
    {
        Name = "Chrome",
        Target = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        Location = "Desktop",
        Arguments = "--incognito",
        IconLocation = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    }
]
```

### Registry Modifications
```toml
[Registry]
Add = [
    {
        Path = "HKLM:\\SOFTWARE\\Test",
        Name = "TestValue",
        Type = "String",
        Value = "Test"
    }
]
Remove = [
    {
        Path = "HKLM:\\SOFTWARE\\OldTest",
        Name = "OldValue"
    }
]
```

### Office Configuration
```toml
[Office]
Channel = "Current"
LanguageID = "en-us"
OfficeClientEdition = 64
DisplayLevel = "Full"
AcceptEULA = true
EnableUpdates = true
RemoveMSI = true
Apps = [
    { ID = "O365ProPlusRetail", PIDKEY = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" }
]
```

### Power Management
```toml
[Power]
MonitorTimeout = 10
DiskTimeout = 20
StandbyTimeout = 30
HibernateTimeout = 0
DisableHibernation = true
```

### Privacy Settings
```toml
[Privacy]
DisableTelemetry = true
DisableAdvertisingID = true
DisableWebSearch = true
DisableAppSuggestions = true
DisableActivityHistory = true
DisableBackgroundApps = true
DisableLocationServices = true
DisableFeedback = true
```

### Command Execution
```toml
[Commands]
Run = [
    { Command = "notepad.exe", Arguments = "test.txt" }
]
CMD = [
    { Command = "echo test" }
]
PowerShell = [
    { Command = "Get-Process" }
]
```

## Environment Variables

WinforgeX supports environment variable expansion in paths and values:

- Use `%VARIABLE%` syntax
- Common variables: `%USERPROFILE%`, `%ProgramFiles%`, `%SystemRoot%`
- Variables are expanded at runtime

## Validation Rules

1. **Boolean Values**
   - Valid: `true`, `false`, `1`, `0`
   - Case-sensitive: use lowercase

2. **Paths**
   - Use double backslashes: `C:\\Path\\To\\File`
   - UNC paths: `\\\\server\\share`
   - Environment variables allowed

3. **Arrays**
   - Must be homogeneous (same type)
   - Can be empty: `[]`
   - One item per line in multi-line format

4. **Required Sections**
   - `System` section is required
   - Other sections are optional

5. **Value Types**
   - String: Use double quotes
   - Numbers: No quotes
   - Boolean: No quotes
   - Arrays: Square brackets
   - Tables: Square brackets for section names

## Best Practices

1. **Organization**
   - Group related settings in sections
   - Use comments to explain settings
   - Keep one setting per line

2. **Security**
   - Encrypt sensitive information
   - Use environment variables for paths
   - Validate paths before deployment

3. **Maintenance**
   - Document all custom settings
   - Version control your configurations
   - Test configurations in a safe environment

## Troubleshooting

Common configuration issues:

1. **Syntax Errors**
   - Missing quotes around strings
   - Wrong number of brackets
   - Missing commas in arrays

2. **Path Issues**
   - Single vs double backslashes
   - Missing environment variables
   - Invalid drive letters

3. **Value Type Errors**
   - Wrong boolean format
   - Quotes around numbers
   - Invalid registry value types

## Additional Resources

- [TOML Documentation](https://toml.io/)
- [TOML Validator](https://www.toml-lint.com/)
- [Environment Variables Reference](https://docs.microsoft.com/en-us/windows/deployment/usmt/usmt-recognized-environment-variables) 