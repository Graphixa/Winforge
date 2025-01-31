# TOML Configuration Guide

WinforgeX uses TOML (Tom's Obvious, Minimal Language) for its configuration files. This guide covers all available configuration sections and their options.

## Configuration Structure

A WinforgeX configuration file is divided into these main sections:

```toml
[System]           # System-level settings
[Activation]       # Windows activation settings
[Applications]     # Software installation and removal
[EnvironmentVariables] # Environment variable settings
[Explorer]         # File Explorer settings
[Taskbar]         # Taskbar customization
[Theme]           # Visual appearance settings
[Tweaks]          # System tweaks and optimizations
[Power]           # Power management settings
[Network]         # Network configuration
[Privacy]         # Privacy settings
[Fonts]           # Font installation
[Google]          # Google product configuration
[Security]        # Security settings
[WindowsUpdate]   # Windows Update configuration
[WindowsFeatures] # Windows features management
[Office]          # Microsoft Office configuration
[Registry]        # Registry modifications
[Tasks]           # Scheduled tasks management
[Commands]        # Custom command execution
[FileOperations]  # File and shortcut operations
```

## System Configuration

The `[System]` section controls core Windows settings:

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

## Activation Configuration

The `[Activation]` section manages Windows activation:

```toml
[Activation]
ProductKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
Version = "Pro"
```

## Application Management

The `[Applications]` section manages software:

```toml
[Applications]
PackageManager = "winget"  # Winget or Chocolatey
Install = ["7zip", "firefox", "vscode", "nodejs"]
Uninstall = ["7zip", "MSEdge"]
RemoveBloatware = true
```

## Environment Variables

The `[EnvironmentVariables]` section manages environment variables:

```toml
[EnvironmentVariables]
User = [
    {VariableName = "TestUserVar", Value = "TestUserVarValue"},
    {VariableName = "TestUserVar2", Value = "TestUserVar2Value"}
]

System = [
    {VariableName = "CompanyName", Value = "Zebra Corp"},
    {VariableName = "Department", Value = "Stripes"}
]
```

## Explorer Configuration

The `[Explorer]` section configures File Explorer:

```toml
[Explorer]
ShowFileExtensions = true
ShowHiddenFolders = true
```

## Taskbar Configuration

The `[Taskbar]` section customizes the taskbar:

```toml
[Taskbar]
TaskbarAlignment = "Left"  # Left or Center
DisableMeetNow = true
DisableWidgets = true
DisableTaskView = true
DisableSearch = true
```

## Theme Configuration

The `[Theme]` section manages visual appearance:

```toml
[Theme]
DarkMode = true
DesktopIconSize = "Medium"  # Small, Medium, Large
WallpaperPath = "https://example.com/wallpaper.jpg"
LockScreenPath = "https://example.com/lockscreen.jpg"
DisableTransparencyEffects = true
DisableWindowsAnimations = true
DisableTransparency = true
```

## Power Management

The `[Power]` section controls power settings:

```toml
[Power]
PowerPlan = "Balanced"
AllowSleep = true
AllowHibernate = true
DisableFastStartup = true
MonitorTimeout = 15  # minutes
SleepTimeout = 30    # minutes
HibernateTimeout = 60  # minutes
```

## Network Configuration

The `[Network]` section manages network settings:

```toml
[Network]
AllowNetworkDiscovery = true
AllowFileAndPrinterSharing = true
MapNetworkDrive = [
    {DriveLetter = "S", Path = "\\\\server\\share", User = "Administrator", Password = "encrypted"},
    {DriveLetter = "T", Path = "\\\\server\\share", User = "Administrator", Password = "encrypted"}
]
```

## Privacy Settings

The `[Privacy]` section manages privacy:

```toml
[Privacy]
DisableTelemetry = true
DisableDiagTrack = true
DisableAppPrivacy = true
DisablePersonalisedAdvertising = true
DisableStartMenuTracking = true
DisableActivityHistory = true
DisableClipboardDataCollection = true
DisableStartMenuSuggestions = true
DisableDiagnosticData = true
DisableWindowsRecall = true
```

## Google Configuration

The `[Google]` section configures Google products:

```toml
[Google]
Drive = [
    {Install = true},
    {DefaultWebBrowser = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
    {DisableOnboardingDialog = true},
    {DisablePhotosSync = true},
    {AutoStartOnLogin = true},
    {OpenOfficeFilesInDocs = true}
]

Chrome = [
    {Install = true},
    {CloudManagementEnrollmentToken = "token"},
    {AlwaysOpenPdfExternally = true},
    {BrowserSignin = 2}  # 0=Disable, 1=Enable, 2=Force
]

GCPW = [
    {Install = true},
    {EnrollmentToken = "token"},
    {DomainsAllowedToLogin = "example.com"}
]
```

## Security Configuration

The `[Security]` section manages security:

```toml
[Security]
DisableMicrosoftDefender = false
DisableAutoPlay = true
Bitlocker = [
    {Drive = "C:", EncryptionMethod = "XtsAes256", EncryptionType = "FullVolume", Password = "encrypted", RecoveryKeyPath = "C:\\Bitlocker\\RecoveryKey.key"}
]
UAC = {Enable = true, Level = "NotifyChanges"}  # AlwaysNotify, NotifyChanges, NotifyNoDesktop, NeverNotify
```

## Windows Update Configuration

The `[WindowsUpdate]` section manages updates:

```toml
[WindowsUpdate]
EnableAutomaticUpdates = true
AUOptions = 3
AutoInstallMinorUpdates = true
ScheduledInstallDay = 1
ScheduledInstallTime = 3
```

## Windows Features

The `[WindowsFeatures]` section manages Windows features:

```toml
[WindowsFeatures]
Enable = [
    "Microsoft-Hyper-V-All",
    "VirtualMachinePlatform"
]
Disable = [
    "Containers-DisposableClientVM"
]
```

## Office Configuration

The `[Office]` section configures Microsoft Office:

```toml
[Office]
LicenseKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
ProductID = "ProPlus2019Retail"
LanguageID = "en-US"
DisplayLevel = "Full"
SetupReboot = "Never"
Channel = "SemiAnnual"
OfficeClientEdition = 64
UpdatesEnabled = true
```

## Registry Configuration

The `[Registry]` section manages registry changes:

```toml
[Registry]
Add = [
    {Name = "DisableLockScreenAppNotifications", Path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System", Type = "DWord", Value = 1, Description = "Disable lock screen app notifications"}
]

Remove = [
    {Name = "DisableLockScreenAppNotifications", Path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"}
]
```

## Tasks Configuration

The `[Tasks]` section manages scheduled tasks:

```toml
[Tasks]
Add = [
    {Name = "AutoShutdown", Path = "https://raw.githubusercontent.com/Graphixa/WinforgeX/main/Tasks/AutoShutdown.xml", Description = "Auto Shutdown"}
]

Remove = [
    {Name = "Task2", Description = "Task 2"}
]

AddRepository = "https://github.com/Graphixa/WinforgeX/tree/main/Tasks/"
```

## Command Execution

The `[Commands]` section allows custom command execution:

```toml
[Commands]
Run = [
    {Program = "calc.exe", Arguments = ""},
    {Program = "cmd.exe", Arguments = "/c echo Hello, World!"}
]

Cmd = [
    {Command = "echo Hello, World! && pause"}
]

Powershell = [
    {Command = "echo Hello, World!"},
    {Command = "New-Item -Path C:\\Temp\\test.txt -ItemType File -Value 'Hello, World!'"}
]
```

## File Operations

The `[FileOperations]` section handles file operations:

```toml
[FileOperations]
Copy = [
    {Source = "\\\\server\\share\\file.txt", Destination = "$env:USERPROFILE\\Documents\\file.txt"}
]

Move = [
    {Source = "C:\\Temp\\file.txt", Destination = "D:\\Temp\\file.txt"}
]

Rename = [
    {Source = "C:\\Temp\\oldname.txt", NewName = "C:\\Temp\\newname.txt"}
]

New = [
    {Type = "File", Path = "C:\\Temp\\newfile.txt"},
    {Type = "Folder", Path = "C:\\Temp\\newfolder"}
]

Delete = [
    {Path = "C:\\Temp\\oldfile.txt"}
]

Shortcut = [
    {Name = "Google Chrome", Target = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", Location = "Desktop", Arguments = "--profile-directory=Default", IconPath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe,0", WorkingDirectory = "C:\\Program Files\\Google\\Chrome\\Application"}
]
```

## Best Practices

1. **Organization**
   - Group related settings together
   - Use descriptive names
   - Comment complex configurations

2. **Security**
   - Encrypt sensitive data (passwords, keys)
   - Use environment variables where appropriate
   - Avoid hardcoding credentials

3. **Maintenance**
   - Version control configurations
   - Document changes
   - Test before deployment

4. **Modularity**
   - Split configurations by role/department
   - Keep configurations DRY

## See Also

- [Examples](Examples) - Real-world configuration examples
- [Security Settings](Security-Settings) - Detailed security configuration
- [Troubleshooting](Troubleshooting) - Configuration troubleshooting guide 