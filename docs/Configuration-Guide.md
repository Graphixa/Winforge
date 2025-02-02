# TOML Configuration Guide

This guide provides a comprehensive reference for all configuration options available in Winforge. Each section includes available options, their types, and example usage.

## Table of Contents

- [TOML Configuration Guide](#toml-configuration-guide)
  - [Table of Contents](#table-of-contents)
  - [Important Notes](#important-notes)
  - [TOML Array Formatting Rules](#toml-array-formatting-rules)
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
> When configuring arrays of objects in your TOML file, it's important to follow the correct formatting rules. 


## TOML Array Formatting Rules
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
| LanguagePacks | Array of valid Windows language pack codes to install (must be seperated by a comma) |



## 🔑 Activation Configuration

The `[Activation]` section manages activation settings.

```toml
[Activation]
ProductKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
Version = "Pro"
```

| Option | Description |
|--------|-------------|
| ProductKey | The Windows product key to activate the system with |
| Version | Windows version to activate as. The version must be one of the following: `Pro`, `Home`, `Education`, `Enterprise` |


## 📦 Applications

The `[Applications]` section manages software installation and removal.

```toml
[Applications]
PackageManager = "winget"  # String: Package manager to use
Install = [
    "Microsoft.VisualStudioCode",
    "Mozilla.Firefox",
    "Git.Git"
]
Uninstall = [
    "Microsoft.BingNews"
]
RemoveBloatware = true   # Boolean: Remove pre-installed bloatware
```

> [!IMPORTANT]
> Package names must be correct as per the package manager selected. You can check package names for chocolatey [here](https://community.chocolatey.org/packages) and winget [here](https://winstall.app/)

| Option | Description |
|--------|-------------|
| PackageManager | Package manager to use. Options:<br>- `winget`: Windows Package Manager (Default)<br>- `chocolatey`: Chocolatey Package Manager |
| Install | Each package name in the array will be installed using the package manager defined in the `PackageManager` key (must be seperated by a comma) |
| Uninstall | Each package name in the array will be unistalled (must be seperated by a comma) |
| RemoveBloatware | `true` to remove Windows bloatware, `false` to do nothing |


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


| Option | Description |
|--------|-------------|
| User | Array of environment variables to be set for the user scope. Each item contains:<br>- `VariableName`: Name of the environment variable<br>- `Value`: Value to set (supports environment variable expansion) |
| System | Array of environment variables to be set for the system scope. Each item contains:<br>- `VariableName`: Name of the environment variable<br>- `Value`: Value to set (supports environment variable expansion) |


## 📂 Explorer Configuration

The `[Explorer]` section manages Windows Explorer settings.

```toml
[Explorer]
ShowFileExtensions = true
ShowHiddenFolders = true
```


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


- **TaskbarAlignment**: Sets the alignment of the taskbar. The alignment must be one of the following:
  - `"Left"` for traditional left alignment
  - `"Center"` for Windows 11 style center alignment

- **DisableMeetNow**: `true` to disable meet now button on the taskbar, `false` to enable

- **DisableWidgets**: `true` to disable widgets on the taskbar, `false` to enable

- **DisableTaskView**: `true` to disable task view on the taskbar, `false` to enable

- **DisableSearch**: `true` to disable search on the taskbar, `false` to enable


## 🎨 Theme Configuration

The `[Theme]` section allows you to manage the theme of the system.

```toml
[Theme]
DarkMode = true
DesktopIconSize = "Medium"
WallpaperPath = "https://example.com/wallpaper.jpg"
LockScreenPath = "https://example.com/lockscreen.png"
DisableTransparencyEffects = true
DisableWindowsAnimations = true
DisableTransparency = true
```


- **DarkMode**: `true` for dark mode, `false` for light mode

- **DesktopIconSize**: Sets the size of the desktop icons. The size must be one of the following:
  - `"Small"` for 24x24 pixels
  - `"Medium"` for 32x32 pixels
  - `"Large"` for 48x48 pixels

- **WallpaperPath**: Sets the wallpaper of the system. The path must be a local file path or a direct HTTP(S) URL to an image file

- **LockScreenPath**: Sets the lock screen of the system. The path must be a local file path or a direct HTTP(S) URL to an image file

- **DisableTransparencyEffects**: `true` to disable transparency effects, `false` to enable

- **DisableWindowsAnimations**: `true` to disable windows animations, `false` to enable

- **DisableTransparency**: `true` to disable transparency, `false` to enable


## 🧰 Tweaks Configuration

The `[Tweaks]` section allows you to manage tweaks settings.

```toml
[Tweaks]
ClassicRightClickMenu = true
GodModeFolder = true
```


- **ClassicRightClickMenu**: Restores the classic right click menu like from Windows 10
  - `true` to enable, `false` to disable

- **GodModeFolder**: Creates a GodMode folder on the desktop which contains all the settings you can change in Windows
  - `true` to create, `false` to remove

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


- **PowerPlan**:
  - `"Balanced"` for default balanced plan
  - `"High performance"` for maximum performance
  - `"Power saver"` for maximum battery life

- **AllowSleep**: `true` to enable sleep, `false` to disable

- **AllowHibernate**: `true` to enable hibernate, `false` to disable

- **DisableFastStartup**: `true` to disable fast startup, `false` to enable

- **MonitorTimeout**: Sets the monitor timeout in minutes. The timeout must be between `1-999` or `0` to never timeout

- **SleepTimeout**: Sets the sleep timeout in minutes. The timeout must be between `1-999` or `0` to never timeout

- **HibernateTimeout**: Sets the hibernate timeout in minutes. The timeout must be between `1-999` or `0` to never timeout

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


- **AllowNetworkDiscovery**: `true` to enable network discovery, `false` to disable

- **AllowFileAndPrinterSharing**: `true` to enable file and printer sharing, `false` to disable

> [!WARNING]
> Passwords are stored in plain text in the TOML file so make sure you encrypt your TOML file if you've got sensitive information in it.
- **MapNetworkDrive**: Array of drive mapping keys value pairs:
  - **DriveLetter**: Single letter `"A-Z"` for mapped drive
  - **Path**: UNC path to network share (e.g. `"\\\\server\\share"`)
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

The `[Fonts]` section allows you to manage fonts.

```toml
[Fonts]
Font = ["roboto", "opensans", "lato", "firasans"]
```


- **Font**: All fonts listed in the array will be installed. You can find font names [here](https://github.com/google/fonts/tree/main/ofl)


## 🏢 Google Configuration

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


- **Drive**: Google Drive configuration array
  - **Install**: Install Google Drive - `true` to install, `false` to uninstall (if already installed)
  - **DefaultWebBrowser**: Sets the default web browser for Google Drive. The path must be a local file path or a direct HTTP(S) URL to an executable file e.g. `"C:\Program Files\Google\Chrome\Application\chrome.exe"`
  - **DisableOnboardingDialog**: Disables Google Drive first-run dialog - `true` to disable, `false` to show
  - **DisablePhotosSync**: Disables photos sync - `true` to disable, `false` to enable
  - **AutoStartOnLogin**: Starts Google Drive with Windows - `true` to enable, `false` to disable
  - **OpenOfficeFilesInDocs**: Opens Office files in Docs - `true` to enable, `false` to disable

- **Chrome**: Google Chrome configuration array
  - **Install**: Install Google Chrome - `true` to install, `false` to uninstall (if already installed)
  - **CloudManagementEnrollmentToken**: Enterprise enrollment token for Google Chrome
  - **AlwaysOpenPdfExternally**: Uses the local PDF viewer instead of Chrome - `true` to use, `false` to use Chrome
  - **BrowserSignin**: Sign-in behavior (0=Disable, 1=Enable, 2=Force)

- **GCPW**: Google Credential Provider for Windows array
  - **Install**: Install Google Credential Provider for Windows - `true` to install, `false` to uninstall (if already installed)
  - **EnrollmentToken**: Enterprise enrollment token for (GCPW) Google Credential Provider for Windows
  - **DomainsAllowedToLogin**: Comma-separated list of allowed domains for (GCPW) Google Credential Provider for Windows


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


> [!WARNING]
> Only disable Windows Defender if you know what your doing. It is an available option but it is not recommended to include in most configurations
- **DisableMicrosoftDefender**: Disables Windows Defender - `true` to disable, `false` to enable
- **DisableAutoPlay**: Disables AutoPlay - `true` to disable, `false` to enable

> [!WARNING]
> It is recommended to use a strong password and ensure you encrypt your configuration file and keep your config file in a secure location.
- **Bitlocker**: Array of BitLocker configurations
  - **Drive**: Drive letter with colon (e.g., "C:")
  - **EncryptionMethod**: Sets the encryption method for BitLocker. The method must be one of the following:
    - `XtsAes128`
    - `XtsAes256` (recommended)
    - `AesCbc128`
    - `AesCbc256`
  - **EncryptionType**: Sets the encryption type for BitLocker. The type must be one of the following:
    - `FullVolume`
    - `UsedSpace`
  - **Password**: This is the password that will be used to encrypt the drive. It must be a string of characters that are 8 characters or more.
  - **RecoveryKeyPath**: Path to save recovery key e.g. `C:\\Bitlocker\\RecoveryKey.key`

- **UAC**: User Account Control settings
  - **Enable**: Enables UAC on the system - `true` to enable, `false` to disable
  - **Level**: Sets the UAC level. The level must be one of the following:
    - `AlwaysNotify`: Most secure - Always notify user of elevation requests
    - `NotifyChanges`: Notify user when programs try to make changes to the system (Default)
    - `NotifyNoDesktop`: No desktop dimming - Notify user of elevation requests but don't dim the desktop
    - `NeverNotify`: Least secure - Never notify user of elevation requests


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


- **EnableAutomaticUpdates**: Enables Windows Update - `true` to enable, `false` to disable
- **AUOptions**: Sets the Windows Update options. The options must be one of the following:
  - `2` - Notify before download
  - `3` - Auto download, notify user for install
  - `4` - Auto download and schedule install
  - `5` - Allow local admin to choose setting
- **AutoInstallMinorUpdates**: Enables automatic installation of minor updates - `true` to enable, `false` to disable
- **ScheduledInstallDay**: Day of week `(0-7)` 0 = Every day, 1 = Sunday, 2 = Monday, 3 = Tuesday, 4 = Wednesday, 5 = Thursday, 6 = Friday, 7 = Saturday
- **ScheduledInstallTime**: Hour of day `(0-23)`


## ⚙️ Windows Features

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


> [!NOTE]
> Feature names must match the Windows optional feature names exactly. Use `Get-WindowsOptionalFeature -Online` in PowerShell to list available features.

- **Enable**: All features listed in the array will be enabled.
- **Disable**: All features listed in the array will be disabled.


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


> [!WARNING]
> License keys are stored in plain text in the TOML file so make sure you encrypt your TOML file if you've got sensitive information in it.

- **LicenseKey**: Valid Office license key
- **ProductID**: Valid Office product ID
- **LanguageID**: Language ID e.g. `en-US` find your language ID [here](https://learn.microsoft.com/en-us/microsoft-365-apps/deploy/overview-deploying-languages-microsoft-365-apps#languages-culture-codes-and-companion-proofing-languages)
- **DisplayLevel**: Sets the display level for the Office installer
  - `None` - Hide the installer
  - `Full` - Show the installer
- **SetupReboot**: Sets the reboot behavior after installation
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


- **Add**: Array of registry values to add/modify
  - **Name**: Registry value name
  - **Path**: Full registry path eg. `HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System`
  - **Type**: Sets the registry value type. The type must be one of the following:
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


- **Add**: All items in this array will be added to the system
  - **Name**: Unique task name
  - **Path**: Local path or URL to task XML file
  - **Description**: Optional task description for your reference. This will not be used by the script

- **Remove**: All items in this array will be removed from the system if found in task scheduler
  - **Name**: Name of task to remove
  - **Description**: Optional task description for your reference. This will not be used by the script

- **AddRepository**: URL to repository containing task XML files


## 🧰 Command Execution

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



- **Run**: All items in this array will be executed as an executable file
  - **Program**: Path or name of executable to be executed e.g. `\\\\server\\share\\program.msi`
  - **Arguments**: Optional command-line arguments e.g. `-silent`

- **Cmd**: All items in this array will be executed using cmd.exe
  - **Command**: CMD command string e.g. `echo Hello, World! && pause`

- **Powershell**: All items in this array will be executed using powershell.exe
  - **Command**: Powershell command to run e.g. `Get-Content C:\\Somefile.txt` or a powershell script e.g. `Get-Content C:\\Scripts\\script.ps1`


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



- **Copy**: All items in this array will be copied to the specified destination
  - **Source**: Source file or folder path to copy from e.g. `\\\\server\\share\\files\\*` or `C:\\Temp\\file.txt` (supports wildcards like * and ?)
  - **Destination**: Target path where files/folders will be copied e.g. `$env:USERPROFILE\\Documents` or `D:\\Backup` (supports environment variables)

- **Move**: All items in this array will be moved (cut and paste) to the destination
  - **Source**: Source file or folder path to move from e.g. `C:\\OldFolder\\file.txt` 
  - **Destination**: Target path where files/folders will be moved to e.g. `D:\\NewFolder` (supports environment variables)

- **Rename**: All items in this array will have their name changed while staying in the same location
  - **Source**: Full path to the file/folder to be renamed e.g. `C:\\Temp\\oldname.txt`
  - **NewName**: New name for the file/folder without the path e.g. `newname.txt` (do not include full path)

- **New**: All items in this array will be created as new files or folders
  - **Type**: Must be either "File" or "Folder" to specify what to create
  - **Path**: Full path where the new file/folder should be created e.g. `C:\\Temp\\newfile.txt` or `C:\\Data\\NewFolder`

- **Delete**: All items in this array will be permanently deleted
  - **Path**: Path to the file/folder to delete e.g. `C:\\Temp\\*.tmp` or `D:\\OldFolder` (supports wildcards for matching multiple items)

- **Shortcut**: All items in this array will be created as a shortcut
  - **Name**: Name of the shortcut once created
  - **Target**: Target program or executable to create the shortcut from e.g. `C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe`
  - **Location**: Options: `Desktop`, `StartMenu`, `Programs`, `CommonDesktop`, `CommonStartMenu`, `CommonPrograms`, `Startup`, `CommonStartup` or use a literal path eg. `C:\\Users\\User\\Desktop`
  - **Arguments**: Optional command-line arguments e.g. `--profile-directory=Default`
  - **IconPath**: Optional path to icon file e.g. `C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe,0`
  - **WorkingDirectory**: Optional working directory e.g. `C:\\Program Files\\Google\\Chrome\\Application`


## Further Reading

- [Examples](/Docs/Examples.md) - Real-world configuration examples
- [Encrypting Your Configuration](/Docs/Encryption-Guide.md) - Detailed security configuration
- [Troubleshooting](/Docs/Troubleshooting.md) - Configuration troubleshooting guide 
- [Winforge.toml](/Docs/winforge.toml) - Example configuration template