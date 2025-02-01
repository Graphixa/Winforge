# TOML Configuration Guide

This guide provides a comprehensive reference for all configuration options available in Winforge. Each section includes available options, their types, and example usage.

## Table of Contents

[Important Notes](#important-notes)
[TOML Array Formatting Rules](#toml-array-formatting-rules)

A Winforge configuration file is divided into these main sections:
[System](#system-configuration)           # System-level settings
[Activation](#activation-configuration)       # Windows activation settings
[Applications](#applications-configuration)     # Software installation and removal
[EnvironmentVariables](#environment-variables-configuration) # Environment variable settings
[Explorer](#explorer-configuration)         # File Explorer settings
[Taskbar](#taskbar-configuration)         # Taskbar customization
[Theme](#theme-configuration)           # Visual appearance settings
[Tweaks](#tweaks-configuration)          # System tweaks and optimizations
[Power](#power-configuration)           # Power management settings
[Network](#network-configuration)         # Network configuration
[Privacy](#privacy-configuration)         # Privacy settings
[Fonts](#fonts-configuration)           # Font installation
[Google](#google-configuration)          # Google product configuration
[Security](#security-configuration)        # Security settings
[WindowsUpdate](#windows-update-configuration)   # Windows Update configuration
[WindowsFeatures](#windows-features) # Windows features management
[Office](#office-configuration)          # Microsoft Office configuration
[Registry](#registry-configuration)        # Registry modifications
[Tasks](#tasks-configuration)           # Scheduled tasks management
[Commands](#command-execution)        # Custom command execution
[FileOperations](#file-operations)  # File and shortcut operations


## Important Notes
> [!NOTE]
> All sections are optional and can be omitted if not needed. Only configure the sections you need.

> [!IMPORTANT]
> All absolute paths must use double backslashes. Example: `\\\\server\\share\\path\\to\\file.txt` or `C:\\path\\to\\file.txt`

> [!WARNING]
> When configuring arrays of objects in your TOML file, it's important to follow the correct formatting rules. 


### TOML Array Formatting Rules
Each object in an array must be defined on a single line with all its properties. Multi-line object definitions are not supported by the parser.

❌ **Example of an incorrect Array Formatting:** - This will cause an error
```toml
Move = [
    {
        Source = "source_path",
        Destination = "dest_path"
    },
    {
        Source = "source_path2",
        Destination = "dest_path2"
    }
]
```

✅ **Example of a correct Array Formatting:** - This will work fine
```toml
Move = [
    {Source = "source_path", Destination = "dest_path"},
    {Source = "source_path2", Destination = "dest_path2"}
]
```


## 🖥️ System Configuration

The `[System]` section controls basic system settings.

```toml
[System]
ComputerName = "WINFORGE-PC"
Locale = "en-US"
Timezone = "UTC"
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

## 🔑 Activation Configuration

The `[Activation]` section manages activation settings.

```toml
[Activation]
ProductKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"  # String: Product key for activation
```

## 📦 Applications

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

## 📚 Environment Variables

The `[EnvironmentVariables]` section manages environment variables.

```toml
[EnvironmentVariables]
User = [
    {VariableName = "PublicPath", Value = "%Path%;C:\\Users\\Public\\Documents"}
]
System = [
    {VariableName = "TEMP", Value = "C:\\Temp"}
]
```

### Available Options:
- **User**: Array of environment variables to be set for the user scope
  - **VariableName**: String: Name of the environment variable
  - **Value**: String: Value to set (supports environment variable expansion)

- **System**: Array of environment variables to be set for the system scope
  - **VariableName**: String: Name of the environment variable
  - **Value**: String: Value to set (supports environment variable expansion)

## 📂 Explorer Configuration

The `[Explorer]` section manages Windows Explorer settings.

```toml
[Explorer]
ShowFileExtensions = true
ShowHiddenFolders = true
```

### Available Options:
- **ShowFileExtensions**: `true` to show file extensions, `false` to hide

- **ShowHiddenFolders**: `true` to show hidden folders, `false` to hide

## 📊 Taskbar Configuration

The `[Taskbar]` section allows you to manage the taskbar.

```toml
[Taskbar]
TaskbarAlignment = "Left"
DisableMeetNow = true
DisableWidgets = true
DisableTaskView = true
DisableSearch = true
```

### Available Options:
- **TaskbarAlignment**: One of:
  - `Left` for traditional left alignment
  - `Center` for Windows 11 style center alignment

- **DisableMeetNow**: `true` to disable, `false` to enable

- **DisableWidgets**: `true` to disable, `false` to enable

- **DisableTaskView**: `true` to disable, `false` to enable

- **DisableSearch**: `true` to disable, `false` to enable

## 🎨 Theme Configuration

The `[Theme]` section allows you to manage the theme of the system.

```toml
[Theme]
DarkMode = true
DesktopIconSize = "Medium"
WallpaperPath = "https://example.com/wallpaper.jpg"
LockScreenPath = "https://example.com/lockscreen.jpg"
DisableTransparencyEffects = true
DisableWindowsAnimations = true
DisableTransparency = true
```

### Available Options:
- **DarkMode**: `true` for dark mode, `false` for light mode

- **DesktopIconSize**: One of:
  - `Small` for 24x24 pixels
  - `Medium` for 32x32 pixels
  - `Large` for 48x48 pixels

- **WallpaperPath**: Local file path or HTTP(S) URL to image directly

- **LockScreenPath**: Local file path or HTTP(S) URL to image directly

- **DisableTransparencyEffects**: `true` to disable, `false` to enable

- **DisableWindowsAnimations**: `true` to disable, `false` to enable

- **DisableTransparency**: `true` to disable, `false` to enable

## 🔋 Power Management

The `[Power]` section configures power settings.

```toml
[Power]
PowerPlan = "Balanced"
AllowSleep = true
AllowHibernate = true
DisableFastStartup = true
MonitorTimeout = 15
SleepTimeout = 30
HibernateTimeout = 60
```

### Available Options:
- **PowerPlan**:
  - `Balanced` for default balanced plan
  - `High performance` for maximum performance
  - `Power saver` for maximum battery life

- **AllowSleep**: `true` to enable, `false` to disable

- **AllowHibernate**: `true` to enable, `false` to disable

- **DisableFastStartup**: `true` to disable, `false` to enable

- **MonitorTimeout**: Integer (minutes, 0-999, 0 = never)

- **SleepTimeout**: Integer (minutes, 0-999, 0 = never)

- **HibernateTimeout**: Integer (minutes, 0-999, 0 = never)

## 🌐 Network Configuration

The `[Network]` section allows you to manage network settings.

```toml
[Network]
AllowNetworkDiscovery = true
AllowFileAndPrinterSharing = true
MapNetworkDrive = [
    {DriveLetter = "S", Path = "\\\\server\\share", User = "Administrator", Password = "encrypted"},
    {DriveLetter = "T", Path = "\\\\server\\share", User = "Administrator", Password = "encrypted"}
]
```

### Available Options:
- **AllowNetworkDiscovery**: `true` to enable, `false` to disable network discovery

- **AllowFileAndPrinterSharing**: `true` to enable, `false` to disable file and printer sharing

> [!WARNING]
> Passwords are stored in plain text in the TOML file so make sure you encrypt your TOML file if you've got sensitive information in it.
- **MapNetworkDrive**: Array of drive mappings with:
  - **DriveLetter**: Single letter `A-Z` for mapped drive
  - **Path**: UNC path to network share (e.g. `\\\\server\\share`)
  - **User**: Username for authentication (optional)
  - **Password**: Password for authentication (optional)



## 🔒 Privacy Settings

The `[Privacy]` section allows you to manage privacy settings.

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

### Available Options:

- **DisableTelemetry**: Windows telemetry data collection - `true` to disable or `false` to enable

- **DisableDiagTrack**: Diagnostic data tracking service - `true` to disable or `false` to enable

- **DisableAppPrivacy**: App access to system features - `true` to disable or `false` to enable

- **DisablePersonalisedAdvertising**: Personalized ad delivery - `true` to disable or `false` to enable

- **DisableStartMenuTracking**: Start menu usage tracking - `true` to disable or `false` to enable

- **DisableActivityHistory**: Windows activity history - `true` to disable or `false` to enable

- **DisableClipboardDataCollection**: Clipboard history feature - `true` to disable or `false` to enable

- **DisableStartMenuSuggestions**: App suggestions in Start menu - `true` to disable or `false` to enable

- **DisableDiagnosticData**: Diagnostic data collection - `true` to disable or `false` to enable

- **DisableWindowsRecall**: Windows recall feature - `true` to disable or `false` to enable

## 🔗 Google Configuration

The `[Google]` section allows you to configure Google Workspace (if required).

```toml
[Google]
Drive = [
    {Install = true},                     
    {DefaultWebBrowser = "path_to_exe"}, # path to browser executable e.g. "C:\Program Files\Google\Chrome\Application\chrome.exe"
    {DisableOnboardingDialog = true}, # disable first-run dialog
    {DisablePhotosSync = true},       # disable photos sync
    {AutoStartOnLogin = true},        # start with Windows
    {OpenOfficeFilesInDocs = true}    # open Office files in Docs
]

Chrome = [
    {Install = true},
    {CloudManagementEnrollmentToken = "############################"}, # Enterprise enrollment token
    {AlwaysOpenPdfExternally = true},          # use system PDF viewer like Adobe Acrobat Reader
    {BrowserSignin = 2}                       # 0=Disable, 1=Enable, 2=Force
]

GCPW = [
    {Install = true},
    {EnrollmentToken = "############################"}, # Enterprise enrollment token
    {DomainsAllowedToLogin = "example.com"}
]
```

### Available Options:
- **Drive**: Google Drive configuration
  - **Install**: Install Google Drive - `true` to install, `false` to uninstall (if already installed)
  - **DefaultWebBrowser**: Path to browser executable e.g. `"C:\Program Files\Google\Chrome\Application\chrome.exe"`
  - **DisableOnboardingDialog**: Disable first-run dialog - `true` to disable, `false` to show
  - **DisablePhotosSync**: Disable photos sync - `true` to disable, `false` to enable
  - **AutoStartOnLogin**: Start with Windows - `true` to enable, `false` to disable
  - **OpenOfficeFilesInDocs**: Open Office files in Docs - `true` to enable, `false` to disable

- **Chrome**: Google Chrome configuration
  - **Install**: Install Google Chrome - `true` to install, `false` to uninstall (if already installed)
  - **CloudManagementEnrollmentToken**: Enterprise enrollment token
  - **AlwaysOpenPdfExternally**: Use system PDF viewer - `true` to use, `false` to use local PDF viewer
  - **BrowserSignin**: Sign-in behavior (0=Disable, 1=Enable, 2=Force)

- **GCPW**: Google Credential Provider for Windows
  - **Install**: Install Google Credential Provider for Windows - `true` to install, `false` to uninstall (if already installed)
  - **EnrollmentToken**: Enterprise enrollment token
  - **DomainsAllowedToLogin**: Comma-separated list of allowed domains

## ⚠️ Security Configuration

The `[Security]` section allows you to manage security settings.

```toml
[Security]
DisableMicrosoftDefender = false # Disable Windows Defender (BE CAREFUL HERE)
DisableAutoPlay = true
Bitlocker = [
    {Drive = "C:", EncryptionMethod = "XtsAes256", EncryptionType = "FullVolume", Password = "encrypted", RecoveryKeyPath = "C:\\Bitlocker\\RecoveryKey.key"}
]
UAC = {Enable = true, Level = "NotifyChanges"}  # AlwaysNotify, NotifyChanges, NotifyNoDesktop, NeverNotify
```

### Available Options:
> [!WARNING]
> Only disable Windows Defender if you know what your doing. It is an available option but it is not recommended to include in most configurations
- **DisableMicrosoftDefender**: `true` to disable, `false` to enable
- 
- **DisableAutoPlay**: `true` to disable, `false` to enable

> [!WARNING]
> It is recommended to use a strong password and ensure you encrypt your configuration file and keep your config file in a secure location.
- **Bitlocker**: Array of BitLocker configurations
  - **Drive**: Drive letter with colon (e.g., "C:")
  - **EncryptionMethod**: One of:
    - `XtsAes128`
    - `XtsAes256` (recommended)
    - `AesCbc128`
    - `AesCbc256`
  - **EncryptionType**: One of:
    - `FullVolume`
    - `UsedSpace`
  - **Password**: Encrypted password string # This is the password that will be used to encrypt the drive. 
  - **RecoveryKeyPath**: Path to save recovery key e.g. `C:\\Bitlocker\\RecoveryKey.key`

- **UAC**: User Account Control settings
  - **Enable**: `true` to enable, `false` to disable UAC on the system
  - **Level**: One of:
    - `AlwaysNotify`: Most secure
    - `NotifyChanges`: Default
    - `NotifyNoDesktop`: No desktop dimming
    - `NeverNotify`: Least secure

## 🔃 Windows Update Configuration

The `[WindowsUpdate]` section allows you to manage Windows Update settings.

```toml
[WindowsUpdate]
EnableAutomaticUpdates = true
AUOptions = 3
AutoInstallMinorUpdates = true
ScheduledInstallDay = 1
ScheduledInstallTime = 3
```

### Available Options:
- **EnableAutomaticUpdates**: `true` to enable, `false` to disable
- **AUOptions** - Auto update options:
  - `2` - Notify before download
  - `3` - Auto download, notify user for install
  - `4` - Auto download and schedule install
  - `5` - Allow local admin to choose setting
- **AutoInstallMinorUpdates**: `true` to enable, `false` to disable
- **ScheduledInstallDay**: Day of week `(0-7)` 0 = Every day, 1 = Sunday, 2 = Monday, 3 = Tuesday, 4 = Wednesday, 5 = Thursday, 6 = Friday, 7 = Saturday
- **ScheduledInstallTime**: Hour of day `(0-23)`

## Windows Features

The `[WindowsFeatures]` section allows you to manage Windows optional features.

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

### Available Options:
- **Enable**: Array of feature names to enable
- **Disable**: Array of feature names to disable

> [!NOTE]
> Feature names must match the Windows optional feature names exactly. Use `Get-WindowsOptionalFeature -Online` in PowerShell to list available features.

## 📄 Office Configuration

The `[Office]` section allows you to configure Microsoft Office.

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

### Available Options:
> [!WARNING]
> License keys are stored in plain text in the TOML file so make sure you encrypt your TOML file if you've got sensitive information in it.
- **LicenseKey**: Valid Office license key
- **ProductID**: Valid Office product ID
- **LanguageID**: Language ID e.g. `en-US` find your language ID [here](https://learn.microsoft.com/en-us/microsoft-365-apps/deploy/overview-deploying-languages-microsoft-365-apps#languages-culture-codes-and-companion-proofing-languages)
- **DisplayLevel**: Relates whether the office installer is shown to the user or is it hidden
  - `None` - Hide the installer
  - `Full` - Show the installer
- **SetupReboot**: One of:
  - `Never` - Do not reboot the system after installation
  - `Always` - Reboot the system after installation

## 🏗️ Registry Configuration

The `[Registry]` section allows you to modify the registry based on the settings you provide.

```toml
[Registry]
Add = [
    {Name = "DisableLockScreenAppNotifications", Path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System", Type = "DWord", Value = 1, Description = "Disables lock screen app notifications"}
]
Remove = [
    {Name = "DisableLockScreenAppNotifications", Path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"}
]
```

### Available Options:
- **Add**: Array of registry values to add/modify
  - **Name**: Registry value name
  - **Path**: Full registry path eg. `HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System`
  - **Type**: One of:
    - `String`
    - `ExpandString`
    - `Binary`
    - `DWord`
    - `QWord`
    - `MultiString`
  - **Value**: Value data (appropriate for Type)
  - **Description**: An optional description for your reference. This will not be used by the script

- **Remove**: Array of registry values to remove
  - **Name**: Registry value name to remove
  - **Path**: Full registry path eg. `HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System`

## ⏲️ ScheduledTasks Configuration

The `[Tasks]` section allows you to manage scheduled tasks.

```toml
[Tasks]
Add = [
    {Name = "AutoShutdown", Path = "https://raw.githubusercontent.com/Graphixa/Winforge/main/Tasks/AutoShutdown.xml", Description = "Auto Shutdown"}
]

Remove = [
    {Name = "UpdateProgramX", Description = "Updates the program X to the latest version"}
]

AddRepository = "https://github.com/Graphixa/Winforge/tree/main/Tasks/" # URL to repository containing task XML files
```

### Available Options:
- **Add**: All items in this array will be added to the system
  - **Name**: Unique task name
  - **Path**: Local path or URL to task XML file
  - **Description**: Optional task description for your reference. This will not be used by the script

- **Remove**: All items in this array will be removed from the system if found in task scheduler
  - **Name**: Name of task to remove
  - **Description**: Optional task description for your reference. This will not be used by the script

- **AddRepository**: URL to repository containing task XML files

## 🧩 Command Execution

The `[Commands]` section allows custom command execution from cmd.exe, powershell.exe and can run executables.

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
    {Command = "New-Item -Path C:\\Temp\\test.txt -ItemType File -Value 'Hello World!'"}
]
```

### Available Options:
- **Run**: All items in this array will be executed as an executable file
  - **Program**: Path or name of executable to be executed e.g. `\\\\server\\share\\program.msi`
  - **Arguments**: Optional command-line arguments e.g. `-silent`

- **Cmd**: All items in this array will be executed using cmd.exe
  - **Command**: CMD command string e.g. `echo Hello, World! && pause`

- **Powershell**: All items in this array will be executed using powershell.exe
  - **Command**: Powershell command to run e.g. Get-Content of a powershell script e.g. `Get-Content C:\\Scripts\\script.ps1`

## 🗄️ File Operations

The `[FileOperations]` section handles file system operations such as copying, moving, renaming, and deleting files.

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

### Available Options:
- **Copy**: Items in this array will be copied to the specified destination
  - **Source**: Source file or folder path to copy from e.g. `\\\\server\\share\\files\\*` or `C:\\Temp\\file.txt` (supports wildcards like * and ?)
  - **Destination**: Target path where files/folders will be copied e.g. `$env:USERPROFILE\\Documents` or `D:\\Backup` (supports environment variables)

- **Move**: Items in this array will be moved (cut and paste) to the destination
  - **Source**: Source file or folder path to move from e.g. `C:\\OldFolder\\file.txt` 
  - **Destination**: Target path where files/folders will be moved to e.g. `D:\\NewFolder` (supports environment variables)

- **Rename**: Items in this array will have their name changed while staying in the same location
  - **Source**: Full path to the file/folder to be renamed e.g. `C:\\Temp\\oldname.txt`
  - **NewName**: New name for the file/folder without the path e.g. `newname.txt` (do not include full path)

- **New**: Items in this array will be created as new files or folders
  - **Type**: Must be either "File" or "Folder" to specify what to create
  - **Path**: Full path where the new file/folder should be created e.g. `C:\\Temp\\newfile.txt` or `C:\\Data\\NewFolder`

- **Delete**: Items in this array will be permanently deleted
  - **Path**: Path to the file/folder to delete e.g. `C:\\Temp\\*.tmp` or `D:\\OldFolder` (supports wildcards for matching multiple items)

- **Shortcut**: Items in this array will be created as a shortcut
  - **Name**: Name of the shortcut once created
  - **Target**: Target program or executable to create the shortcut from e.g. `C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe`
  - **Location**: Options: `Desktop`, `StartMenu`, `Programs`, `CommonDesktop`, `CommonStartMenu`, `CommonPrograms`, `Startup`, `CommonStartup` or use a literal path eg. `C:\\Users\\User\\Desktop`
  - **Arguments**: Optional command-line arguments e.g. `--profile-directory=Default`
  - **IconPath**: Optional path to icon file e.g. `C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe,0`
  - **WorkingDirectory**: Optional working directory e.g. `C:\\Program Files\\Google\\Chrome\\Application`


## See Also

- [Examples](Examples) - Real-world configuration examples
- [Security Settings](Security-Settings) - Detailed security configuration
- [Troubleshooting](Troubleshooting) - Configuration troubleshooting guide 
- [Winforge.toml](winforge.toml) - Example configuration file