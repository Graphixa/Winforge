# YAML Configuration Guide

This guide provides a comprehensive reference for all configuration options available in Winforge. Each section includes available options, their types, and example usage.

## Table of Contents

- [YAML Configuration Guide](#yaml-configuration-guide)
  - [Table of Contents](#table-of-contents)
  - [Important Notes](#important-notes)
  - [YAML Syntax Guidelines](#yaml-syntax-guidelines)
  - [🖥️ System Configuration](#️-system-configuration)
  - [🔑 Activation Configuration](#-activation-configuration)
  - [📦 Applications](#-applications)
  - [📚 Environment Variables](#-environment-variables)
  - [📂 Explorer Configuration](#-explorer-configuration)
  - [📊 Taskbar Configuration](#-taskbar-configuration)
  - [🎨 Theme Configuration](#-theme-configuration)
  - [🧰 Tweaks Configuration](#-tweaks-configuration)
  - [🔋 Power Management](#-power-management)
  - [🌐 Network Configuration](#-network-configuration)
  - [🔒 Privacy Settings](#-privacy-settings)
  - [🔠 Fonts Configuration](#-fonts-configuration)
  - [🏢 Google Configuration](#-google-configuration)
  - [⚠️ Security Configuration](#️-security-configuration)
  - [🛡️ Windows Defender Configuration](#️-windows-defender-configuration)
  - [🔃 Windows Update Configuration](#-windows-update-configuration)
  - [⚙️ Windows Features](#️-windows-features)
  - [📄 Office Configuration](#-office-configuration)
  - [🏗️ Registry Configuration](#️-registry-configuration)
  - [⏲️ ScheduledTasks Configuration](#️-scheduledtasks-configuration)
  - [🧰 Command Execution](#-command-execution)
  - [🗄️ File Operations](#️-file-operations)
  - [Further Reading](#further-reading)

## Important Notes
> [!NOTE]
> All sections are optional and can be omitted if not needed. Only configure the sections you need.

> [!IMPORTANT]
> All absolute paths must use double backslashes. Example: `\\\\server\\share\\path\\to\\file.txt` or `C:\\path\\to\\file.txt`

> [!WARNING]
> Passwords are stored in plain text in the YAML file so make sure you encrypt your YAML file if you've got sensitive information in it.

## YAML Syntax Guidelines
YAML uses indentation to represent structure. Here are key formatting rules:

✅ **Correct YAML formatting:**
```yaml
Applications:
  Install:
    - App: "firefox"
      Version: "119.0.1"
    - App: "vscode"
```

❌ **Incorrect YAML formatting:**
```yaml
Applications:
Install:  # Missing proper indentation
- App: "firefox"
Version: "119.0.1"  # Not properly nested
```

## 🖥️ System Configuration

The `System` section controls basic system settings.

```yaml
System:
  ComputerName: "Winforge"
  Locale: "en-US"
  Timezone: "AU"
  DisableWindowsStore: true
  DisableOneDrive: true
  DisableCopilot: true
  DisableWindowsRecall: true
  DisableRemoteDesktop: true
  DisableSetupDevicePrompt: true
  LanguagePacks:
    - "en-US"
    - "en-GB"
```

| Option | Description |
|--------|-------------|
| ComputerName | Sets the computer name of the system (up to 15 characters, no special chars except for hyphens `-`) |
| Locale | Sets the locale of the system (see [Language Codes](https://learn.microsoft.com/en-us/windows/win32/intl/language-identifier-constants-and-strings) for supported locales) |
| Timezone | Sets the time zone of the system (see [Time Zones](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-time-zones) for supported time zones) |
| DisableWindowsStore | `true` to disable windows store, `false` to enable |
| DisableOneDrive | `true` to disable one drive, `false` to enable |
| DisableCopilot | `true` to disable copilot, `false` to enable |
| DisableWindowsRecall | `true` to disable windows recall, `false` to enable |
| DisableRemoteDesktop | `true` to disable remote desktop, `false` to enable |
| DisableSetupDevicePrompt | `true` to disable setup device prompt, `false` to enable |
| LanguagePacks | Array of valid Windows language pack codes to install |

## 🔑 Activation Configuration

The `Activation` section manages activation settings.

```yaml
Activation:
  ProductKey: "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
  Version: "Pro"
```

| Option | Description |
|--------|-------------|
| ProductKey | The Windows product key to activate the system with |
| Version | Windows version to activate as. Options: `Pro`, `Home`, `Education`, `Enterprise` |

## 📦 Applications

The `Applications` section manages software installation and removal with version support.

```yaml
Applications:
  PackageManager: "chocolatey"  # winget or chocolatey
  RemoveBloatware: true
  Install:
    - App: "7zip"
      Version: "19.00"
    - App: "firefox"
      Version: "119.0.1"
    - App: "vscode"  # No version = latest
    - App: "nodejs"
      Version: "20.9.0"
  Uninstall:
    - App: "7zip"
    - App: "firefox"
```

> [!IMPORTANT]
> Package names must be correct as per the package manager selected. You can check package names for chocolatey [here](https://community.chocolatey.org/packages) and winget [here](https://winstall.app/)

| Option | Description |
|--------|-------------|
| PackageManager | Package manager to use. Options:<br>- `winget`: Windows Package Manager<br>- `chocolatey`: Chocolatey Package Manager |
| Install | Array of applications to install. Each can be:<br>- Simple string: `"appname"`<br>- Object with version: `App: "appname"` and `Version: "1.0"` |
| Uninstall | Array of applications to uninstall using `App:` property |
| RemoveBloatware | `true` to remove Windows bloatware, `false` to do nothing |

## 📚 Environment Variables

The `EnvironmentVariables` section manages environment variables with the `Name` property.

```yaml
EnvironmentVariables:
  User:  # Sets environment variables for the user scope
    - Name: "PythonPath"
      Value: "C:\\Python312"
    - Name: "NodePath"
      Value: "C:\\Program Files\\nodejs"
  System:  # Sets environment variables for the system scope
    - Name: "CompanyName"
      Value: "Cyberdyne Systems"
    - Name: "Department"
      Value: "Machine Research"
```

| Option | Description |
|--------|-------------|
| User | Array of environment variables to be set for the user scope. Each item contains:<br>- `Name`: Name of the environment variable<br>- `Value`: Value to set (supports environment variable expansion) |
| System | Array of environment variables to be set for the system scope. Each item contains:<br>- `Name`: Name of the environment variable<br>- `Value`: Value to set (supports environment variable expansion) |

## 📂 Explorer Configuration

The `Explorer` section manages Windows Explorer settings.

```yaml
Explorer:
  ShowFileExtensions: true
  ShowHiddenFolders: true
```

- **ShowFileExtensions**: `true` to show file extensions, `false` to hide
- **ShowHiddenFolders**: `true` to show hidden folders, `false` to hide

## 📊 Taskbar Configuration

The `Taskbar` section allows you to manage the taskbar.

```yaml
Taskbar:
  TaskbarAlignment: "Left"  # Left or Center
  DisableMeetNow: true
  DisableWidgets: true
  DisableTaskView: true
  DisableSearch: true
```

- **TaskbarAlignment**: Sets the alignment of the taskbar. Options: `"Left"` or `"Center"`
- **DisableMeetNow**: `true` to disable meet now button on the taskbar, `false` to enable
- **DisableWidgets**: `true` to disable widgets on the taskbar, `false` to enable
- **DisableTaskView**: `true` to disable task view on the taskbar, `false` to enable
- **DisableSearch**: `true` to disable search on the taskbar, `false` to enable

## 🎨 Theme Configuration

The `Theme` section allows you to manage the theme of the system.

```yaml
Theme:
  DarkMode: true
  DesktopIconSize: "Medium"  # Small, Medium, Large
  WallpaperPath: "https://images.pexels.com/photos/2085998/pexels-photo-2085998.jpeg"
  LockScreenPath: "https://images.pexels.com/photos/2341830/pexels-photo-2341830.jpeg"
  DisableTransparencyEffects: true
  DisableWindowsAnimations: true
  DisableTransparency: true
```

- **DarkMode**: `true` for dark mode, `false` for light mode
- **DesktopIconSize**: Sets the size of desktop icons. Options: `"Small"`, `"Medium"`, `"Large"`
- **WallpaperPath**: Sets the wallpaper. Local path or direct HTTP(S) URL to an image file
- **LockScreenPath**: Sets the lock screen. Local path or direct HTTP(S) URL to an image file
- **DisableTransparencyEffects**: `true` to disable transparency effects, `false` to enable
- **DisableWindowsAnimations**: `true` to disable windows animations, `false` to enable
- **DisableTransparency**: `true` to disable transparency, `false` to enable

## 🧰 Tweaks Configuration

The `Tweaks` section allows you to manage tweaks settings.

```yaml
Tweaks:
  ClassicRightClickMenu: true
  GodModeFolder: true
```

- **ClassicRightClickMenu**: `true` to enable classic right click menu, `false` to disable
- **GodModeFolder**: `true` to create GodMode folder on desktop, `false` to remove

## 🔋 Power Management

The `Power` section configures power settings.

```yaml
Power:
  PowerPlan: "Balanced"
  AllowSleep: true
  AllowHibernate: true
  DisableFastStartup: true
  MonitorTimeout: 15  # minutes (integer)
  SleepTimeout: 30    # minutes (integer)
  HibernateTimeout: 60  # minutes (integer)
```

- **PowerPlan**: Options: `"Balanced"`, `"High performance"`, `"Power saver"`
- **AllowSleep**: `true` to enable sleep, `false` to disable
- **AllowHibernate**: `true` to enable hibernate, `false` to disable
- **DisableFastStartup**: `true` to disable fast startup, `false` to enable
- **MonitorTimeout**: Monitor timeout in minutes (1-999 or 0 for never)
- **SleepTimeout**: Sleep timeout in minutes (1-999 or 0 for never)
- **HibernateTimeout**: Hibernate timeout in minutes (1-999 or 0 for never)

## 🌐 Network Configuration

The `Network` section allows you to manage network settings with consistent naming.

```yaml
Network:
  EnableNetworkDiscovery: true
  EnableFileAndPrinterSharing: true
  MapNetworkDrive:
    - DriveLetter: "S"
      Path: "\\\\192.168.0.10\\Media"
      Username: "Administrator"
      Password: "Password123"
    - DriveLetter: "T"
      Path: "\\\\192.168.0.10\\Media"
      Username: "Administrator"
      Password: "Password123"
```

- **EnableNetworkDiscovery**: `true` to enable network discovery, `false` to disable
- **EnableFileAndPrinterSharing**: `true` to enable file and printer sharing, `false` to disable
- **MapNetworkDrive**: Array of drive mappings with flattened credentials:
  - **DriveLetter**: Single letter "A-Z" for mapped drive
  - **Path**: UNC path to network share (e.g. `"\\\\server\\share"`)
  - **Username**: Username for authentication (optional)
  - **Password**: Password for authentication (optional)

> All absolute paths must use double backslashes

## 🔒 Privacy Settings

The `Privacy` section allows you to manage privacy settings.

```yaml
Privacy:
  DisableTelemetry: true
  DisableDiagTrack: true
  DisableAppPrivacy: true
  DisablePersonalisedAdvertising: true
  DisableStartMenuTracking: true
  DisableActivityHistory: true
  DisableClipboardDataCollection: true
  DisableStartMenuSuggestions: true
  DisableDiagnosticData: true
  DisableWindowsRecall: true
```

- **DisableTelemetry**: Windows telemetry data collection - `true` to disable, `false` to enable
- **DisableDiagTrack**: Diagnostic data tracking service - `true` to disable, `false` to enable
- **DisableAppPrivacy**: App access to system features - `true` to disable, `false` to enable
- **DisablePersonalisedAdvertising**: Personalized ad delivery - `true` to disable, `false` to enable
- **DisableStartMenuTracking**: Start menu usage tracking - `true` to disable, `false` to enable
- **DisableActivityHistory**: Windows activity history - `true` to disable, `false` to enable
- **DisableClipboardDataCollection**: Clipboard history feature - `true` to disable, `false` to enable
- **DisableStartMenuSuggestions**: App suggestions in Start menu - `true` to disable, `false` to enable
- **DisableDiagnosticData**: Diagnostic data collection - `true` to disable, `false` to enable
- **DisableWindowsRecall**: Windows recall feature - `true` to disable, `false` to enable

## 🔠 Fonts Configuration

The `Fonts` section allows you to manage fonts with direct array structure.

```yaml
Fonts:
  - "roboto"
  - "opensans"
  - "lato"
  - "firasans"
```

- **Fonts**: Direct array of font names to install. Find font names [here](https://github.com/google/fonts/tree/main/ofl)

## 🏢 Google Configuration

The `Google` section allows you to configure Google Workspace with object structure.

```yaml
Google:
  Drive:  # Google Drive configuration
    Install: true
    DefaultWebBrowser: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    DisableOnboardingDialog: true
    DisablePhotosSync: true
    AutoStartOnLogin: true
    OpenOfficeFilesInDocs: true
  Chrome:  # Chrome configuration
    Install: true
    CloudManagementEnrollmentToken: "10010000000000000000000000000000001"
    AlwaysOpenPdfExternally: true
    BrowserSignin: 2  # 0=Disable, 1=Enable, 2=Force
  GCPW:  # Google Credential Provider for Windows configuration
    Install: true
    EnrollmentToken: "10010000000000000000000000000000001"
    DomainsAllowedToLogin: "example.com"
```

- **Drive**: Google Drive configuration object
  - **Install**: `true` to install, `false` to uninstall
  - **DefaultWebBrowser**: Path to browser executable
  - **DisableOnboardingDialog**: `true` to disable first-run dialog
  - **DisablePhotosSync**: `true` to disable photos sync
  - **AutoStartOnLogin**: `true` to start with Windows
  - **OpenOfficeFilesInDocs**: `true` to open Office files in Docs

- **Chrome**: Google Chrome configuration object
  - **Install**: `true` to install, `false` to uninstall
  - **CloudManagementEnrollmentToken**: Enterprise enrollment token
  - **AlwaysOpenPdfExternally**: `true` to use system PDF viewer
  - **BrowserSignin**: Sign-in behavior (0=Disable, 1=Enable, 2=Force)

- **GCPW**: Google Credential Provider for Windows object
  - **Install**: `true` to install, `false` to uninstall
  - **EnrollmentToken**: Enterprise enrollment token
  - **DomainsAllowedToLogin**: Allowed domains for login

## ⚠️ Security Configuration

The `Security` section allows you to manage security settings.

```yaml
Security:
  DisableAutoPlay: true
  UAC:
    Enable: true
    Level: "NotifyChanges"  # Options: "AlwaysNotify", "NotifyChanges", "NotifyNoDesktop", "NeverNotify"
```

- **DisableAutoPlay**: `true` to disable AutoPlay, `false` to enable
- **UAC**: User Account Control settings
  - **Enable**: `true` to enable UAC, `false` to disable
  - **Level**: UAC notification level

## 🛡️ Windows Defender Configuration

The `WindowsDefender` section provides granular control over Windows Defender.

```yaml
WindowsDefender:
  RealTimeProtection: true
  CloudProtection: true
  AutomaticSampleSubmission: false
  NetworkProtection: true
  ControlledFolderAccess: false
  AttackSurfaceReduction: true
  ExclusionPaths:
    - "C:\\MyApp\\"
    - "C:\\Temp\\"
  ExclusionExtensions:
    - ".tmp"
    - ".log"
  ExclusionProcesses:
    - "myapp.exe"
    - "backup.exe"
  ScanSettings:
    QuickScanTime: "02:00"  # 2 AM daily quick scan (00:00 - 23:59)
    FullScanDay: "Sunday"   # Weekly full scan on Sunday (Monday - Sunday)
    ScanRemovableDrives: true
    ScanArchives: true
    ScanNetworkFiles: false
  ThreatSettings:
    DefaultAction: "Quarantine"  # Options: "Clean", "Quarantine", "Remove", "Allow", "UserDefined", "Block"
    SubmitSamplesConsent: "SendSafeSamples"  # Options: "AlwaysPrompt", "SendSafeSamples", "NeverSend", "SendAllSamples"
    MAPSReporting: "Advanced"  # Options: "Disabled", "Basic", "Advanced"
```

## 🔃 Windows Update Configuration

The `WindowsUpdate` section allows you to manage Windows Update settings.

```yaml
WindowsUpdate:
  EnableAutomaticUpdates: true
  AUOptions: 3  # 0=Automatic, 1=Notify, 2=NotifyChanges, 3=NotifyChangesAndRestart, 4=NotifyChangesAndRestartIfRequired
  AutoInstallMinorUpdates: true
  ScheduledInstallDay: 1  # 1-7 (1=Monday, 7=Sunday)
  ScheduledInstallTime: 3  # 0-23 (3=3 AM)
```

- **EnableAutomaticUpdates**: `true` to enable Windows Update, `false` to disable
- **AUOptions**: Update behavior (2=Notify, 3=Auto download/notify, 4=Auto download/install)
- **AutoInstallMinorUpdates**: `true` to enable automatic minor updates
- **ScheduledInstallDay**: Day of week (1=Monday, 7=Sunday)
- **ScheduledInstallTime**: Hour of day (0-23)

## ⚙️ Windows Features

The `WindowsFeatures` section allows you to manage Windows optional features.

```yaml
WindowsFeatures:
  Enable:
    - "Microsoft-Hyper-V-All"
    - "Containers-DisposableClientVM"
    - "Microsoft-RemoteDesktopConnection"
    - "VirtualMachinePlatform"
  Disable:
    - "Containers-DisposableClientVM"
```

> [!NOTE]
> Feature names must match Windows optional feature names exactly. Use `Get-WindowsOptionalFeature -Online` in PowerShell to list available features.

- **Enable**: Array of features to enable
- **Disable**: Array of features to disable

## 📄 Office Configuration

The `Office` section allows you to configure Microsoft Office.

```yaml
Office:
  LicenseKey: "NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP"
  ProductID: "ProPlus2019Retail"
  LanguageID: "en-US"
  DisplayLevel: "None"
  SetupReboot: "Never"
  Channel: "SemiAnnual"
  OfficeClientEdition: 64
  UpdatesEnabled: true
```

- **LicenseKey**: Valid Office license key
- **ProductID**: Valid Office product ID
- **LanguageID**: Language ID (e.g. "en-US")
- **DisplayLevel**: Installer display ("None" or "Full")
- **SetupReboot**: Reboot behavior ("Never" or "Always")
- **Channel**: Update channel
- **OfficeClientEdition**: Architecture (32 or 64)
- **UpdatesEnabled**: `true` to enable updates

## 🏗️ Registry Configuration

The `Registry` section allows you to modify the windows registry.

```yaml
Registry:
  Add:
    - Name: "DisableLockScreenAppNotifications"
      Path: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"
      Type: "DWord"
      Value: 1
      Description: "Disable lock screen app notifications"
  Remove:
    - Name: "DisableLockScreenAppNotifications"
      Path: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"
```

- **Add**: Array of registry values to add/modify
- **Remove**: Array of registry values to remove

## ⏲️ ScheduledTasks Configuration

The `Tasks` section allows you to manage scheduled tasks.

```yaml
Tasks:
  Add:
    - Name: "AutoShutdown"
      Path: "https://raw.githubusercontent.com/Graphixa/WinforgeX/main/Tasks/AutoShutdown.xml"
      Description: "Auto Shutdown"
  Remove:
    - Name: "Task2"
      Description: "Task 2"
  AddRepository: "https://github.com/Graphixa/Winforge/tree/main/Tasks/"
```

## 🧰 Command Execution

The `Commands` section allows custom command execution.

```yaml
Commands:
  Run:
    - Program: "calc.exe"
      Arguments: ""
    - Program: "cmd.exe"
      Arguments: "/c echo Hello, World!"
  Cmd:
    - Command: "echo Hello, World! && pause"
  Powershell:
    - Command: "echo Hello, World!"
    - Command: "New-Item -Path C:\\Temp\\test.txt -ItemType File -Value 'Hello, World!'"
```

## 🗄️ File Operations

The `FileOperations` section handles file system operations.

```yaml
FileOperations:
  Copy:
    - Source: "\\\\server\\share\\file.txt"
      Destination: "$env:USERPROFILE\\Documents\\file.txt"
  Move:
    - Source: "C:\\Temp\\file.txt"
      Destination: "D:\\Temp\\file.txt"
  Rename:
    - Source: "C:\\Temp\\oldname.txt"
      NewName: "C:\\Temp\\newname.txt"
  New:
    - Type: "File"
      Path: "C:\\Temp\\newfile.txt"
    - Type: "Folder"
      Path: "C:\\Temp\\newfolder"
  Delete:
    - Path: "C:\\Temp\\oldfolder"
    - Path: "C:\\Temp\\oldfile.txt"
  Shortcut:
    - Name: "Google Chrome"
      Target: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
      Location: "Desktop"
      Arguments: "--profile-directory=Default"
      IconPath: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe,0"
      WorkingDirectory: "C:\\Program Files\\Google\\Chrome\\Application"
```

## Further Reading

- [Getting Started](/docs/Getting-Started.md) - Quick setup guide
- [Examples](/examples/) - Real-world configuration examples
- [Encrypting Your Configuration](/docs/Encryption-Guide.md) - Security configuration
- [Troubleshooting](/docs/Troubleshooting.md) - Configuration troubleshooting guide