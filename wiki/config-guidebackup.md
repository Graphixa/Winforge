# TOML Configuration Guide

This guide provides a comprehensive reference for all configuration options available in WinforgeX. Each section includes available options, their types, and example usage.

## Table of Contents

- [TOML Configuration Guide](#toml-configuration-guide)
  - [Table of Contents](#table-of-contents)
  - [System Configuration](#system-configuration)
    - [Available Options:](#available-options)
  - [Activation Configuration](#activation-configuration)
  - [Applications](#applications)
    - [Available Options:](#available-options-1)
  - [Network Settings](#network-settings)
    - [Available Options](#available-options-2)
  - [Privacy Settings](#privacy-settings)
    - [Available Options](#available-options-3)
  - [Theme and UI](#theme-and-ui)
    - [Available Options](#available-options-4)
  - [Power Management](#power-management)
    - [Available Options](#available-options-5)
  - [Environment Variables](#environment-variables)
    - [Available Options](#available-options-6)
  - [Commands](#commands)
    - [Available Options](#available-options-7)
  - [File Operations](#file-operations)
    - [Available Options](#available-options-8)
  - [Windows Features](#windows-features)
    - [Available Options](#available-options-9)
  - [Windows Update](#windows-update)
    - [Available Options](#available-options-10)
  - [Office Configuration](#office-configuration)
    - [Available Options](#available-options-11)
  - [Best Practices](#best-practices)
  - [Examples](#examples)


> [!IMPORTANT]
> Array cannot be multiline.
> 
> Array values must be seperated by a comma.
> 
> Array values must be enclosed in quotes if they contain spaces.

> Backslashes must be escaped with a backslash. eg. `C:\\path\\to\\file.txt`

Example of a valid array:

```toml
[Tasks]
Tasks = [
    { Name = "Task1", Command = "ipconfig /flushdns" },
    { Name = "Task2", Command = "net user administrator /active:yes" }
]
```

Example of an invalid array:

```toml
[Tasks]
Tasks = [
    { Name = "Task1", 
      Path = "C:\\path\\to\\file.xml" },
    { Name = "Task2", 
      Path = "C:\\path\\to\\file.xml" }
]
```

## System Configuration

The `[System]` section controls basic system settings.

```toml
[System]
ComputerName = "WINFORGE-PC"
Locale = "en-US"
Timezone = "AU"
DisableWindowsStore = true
DisableOneDrive = true
DisableCopilot = true
DisableWindowsRecall = true
DisableRemoteDesktop = true
DisableSetupDevicePrompt = true
LanguagePacks = ["en-US", "en-GB"]
```

### Available Options:
- **ComputerName**: Any valid Windows computer name (up to 15 characters, no special chars except hyphens)
- **Locale**: Any valid Windows locale identifier (see [Language Codes](https://learn.microsoft.com/en-us/windows/win32/intl/language-identifier-constants-and-strings))
- **Timezone**: Valid Windows time zone ID (see [Time Zones](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-time-zones))
- **DisableWindowsStore**: `true` to disable, `false` to enable
- **DisableOneDrive**: `true` to disable, `false` to enable
- **DisableCopilot**: `true` to disable, `false` to enable
- **DisableWindowsRecall**: `true` to disable, `false` to enable
- **DisableRemoteDesktop**: `true` to disable, `false` to enable
- **DisableSetupDevicePrompt**: `true` to disable, `false` to enable
- **LanguagePacks**: Array of valid Windows language pack codes

## Activation Configuration

The `[Activation]` section manages activation settings.

```toml
[Activation]
ProductKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"  # String: Product key for activation
```

## Applications

The `[Applications]` section manages software installation and removal.

```toml
[Applications]
PackageManager = "winget"  # String: Package manager to use
Install = [               # Array: Applications to install
    "Microsoft.VisualStudioCode",
    "Mozilla.Firefox",
    "Git.Git"
]
Uninstall = [            # Array: Applications to remove
    "Microsoft.BingNews"
]
RemoveBloatware = true   # Boolean: Remove pre-installed bloatware
```

### Available Options:
- **PackageManager**:
  - "winget": Windows Package Manager
  - "chocolatey": Chocolatey Package Manager

> [!IMPORTANT]
> Package names must be correct as per the package manager selected. You can check package names for chocolatey [here](https://community.chocolatey.org/packages) and winget [here](https://winstall.app/)
- **Install**: Array of valid package names seperated by a comma
- **Uninstall**: Array of valid package names seperated by a comma
- **RemoveBloatware**: `true` to remove Windows bloatware, `false` to keep

## Network Settings

The `[Network]` section configures network-related settings.

```toml
[Network]
MapDrive = [
    { Letter = "S", Path = "\\\\server\\share", Persistent = true }
]
EnableNetworkDiscovery = true  # Boolean: Enable network discovery
```

### Available Options

- **MapDrive**: Array of network drives to map
- **EnableNetworkDiscovery**: `true` to enable, `false` to disable


## Privacy Settings

The `[Privacy]` section manages Windows privacy settings.

```toml
[Privacy]
DisableTelemetry = true           # Boolean: Disable telemetry
DisableAdvertisingID = true       # Boolean: Disable advertising ID
DisableWebSearch = true           # Boolean: Disable web search
DisableLocationTracking = true    # Boolean: Disable location tracking
```

### Available Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| DisableTelemetry | Boolean | Disable telemetry data collection | false |
| DisableAdvertisingID | Boolean | Disable advertising ID | false |
| DisableWebSearch | Boolean | Disable web search in Start menu | false |
| DisableLocationTracking | Boolean | Disable location services | false |

## Theme and UI

The `[Theme]` section controls Windows appearance settings.

```toml
[Theme]
DarkMode = true              # Boolean: Enable dark mode
DesktopIconSize = "medium"   # String: Desktop icon size
Wallpaper = "C:\\path\\to\\wallpaper.jpg"  # String: Desktop wallpaper path
```

### Available Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| DarkMode | Boolean | Enable dark mode | false |
| DesktopIconSize | String | Icon size ("small", "medium", "large") | "medium" |
| Wallpaper | String | Path to wallpaper image | Current wallpaper |

## Power Management

The `[Power]` section configures power settings.

```toml
[Power]
PowerPlan = "Balanced"    # String: Power plan to use
AllowSleep = true        # Boolean: Allow system sleep
SleepTimeout = 30        # Integer: Minutes until sleep
```

### Available Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| PowerPlan | String | Power plan ("Balanced", "High performance", "Power saver") | "Balanced" |
| AllowSleep | Boolean | Allow system sleep | true |
| SleepTimeout | Integer | Minutes until sleep (0 = never) | 30 |

## Environment Variables

The `[EnvironmentVariables]` section manages environment variables.

```toml
[EnvironmentVariables]
Path = [                 # Array: Paths to add to PATH
    "%USERPROFILE%\\.local\\bin"
]
Custom = [               # Array: Custom environment variables
    { Name = "JAVA_HOME", Value = "C:\\Program Files\\Java\\jdk-17" }
]
```

### Available Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| Path | Array | Paths to add to PATH variable | [] |
| Custom | Array | Custom environment variables | [] |

## Commands

The `[Commands]` section defines commands to execute.

```toml
[Commands]
Run = [                  # Array: Commands to run
    "ipconfig /flushdns"
]
PowerShell = [           # Array: PowerShell commands
    "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux"
]
Cmd = [                  # Array: CMD commands
    "net user administrator /active:yes"
]
```

### Available Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| Run | Array | General commands to execute | [] |
| PowerShell | Array | PowerShell commands to execute | [] |
| Cmd | Array | CMD commands to execute | [] |

## File Operations

The `[FileOperations]` section manages file operations.

```toml
[FileOperations]
Copy = [                # Array: Files to copy
    { Source = "C:\\source\\file.txt", Destination = "C:\\dest\\file.txt" }
]
Move = [                # Array: Files to move
    { Source = "C:\\source\\file.txt", Destination = "C:\\dest\\file.txt" }
]
Delete = [              # Array: Files to delete
    "C:\\temp\\file.txt"
]
```

### Available Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| Copy | Array | Files to copy | [] |
| Move | Array | Files to move | [] |
| Delete | Array | Files to delete | [] |

## Windows Features

The `[WindowsFeatures]` section manages Windows optional features.

```toml
[WindowsFeatures]
Enable = [              # Array: Features to enable
    "Microsoft-Windows-Subsystem-Linux",
    "VirtualMachinePlatform"
]
Disable = [             # Array: Features to disable
    "Internet-Explorer-Optional-amd64"
]
```

### Available Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| Enable | Array | Features to enable | [] |
| Disable | Array | Features to disable | [] |

## Windows Update

The `[WindowsUpdate]` section configures Windows Update settings.

```toml
[WindowsUpdate]
AutoUpdate = true       # Boolean: Enable automatic updates
DeferFeatureUpdates = true  # Boolean: Defer feature updates
DeferQualityUpdates = true  # Boolean: Defer quality updates
```

### Available Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| AutoUpdate | Boolean | Enable automatic updates | true |
| DeferFeatureUpdates | Boolean | Defer feature updates | false |
| DeferQualityUpdates | Boolean | Defer quality updates | false |

## Office Configuration

The `[Office]` section manages Microsoft Office settings.

```toml
[Office]
Version = "O365ProPlus"  # String: Office version
ProductKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"  # String: Product key
```

### Available Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| Version | String | Office version | Current version |
| ProductKey | String | Product key for activation | None |

## Best Practices

1. **Organization**
   - Group related settings together
   - Use comments to document complex configurations
   - Keep sensitive information in separate files

2. **Security**
   - Use environment variables for sensitive data
   - Review commands before execution
   - Use secure paths for file operations

3. **Maintenance**
   - Document your configurations
   - Use version control
   - Test configurations in a safe environment

## Examples

See the [Examples](Examples) section for complete configuration examples for different scenarios. 