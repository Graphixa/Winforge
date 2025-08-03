# Winforge Refactor Plan

## Overview

Separate Winforge into CLI and GUI components while maintaining backward compatibility.

## Architecture

### 1. winforge.ps1 (CLI Only)
- **With parameters**: `irm method with winforge.ps1 -ConfigPath "config.yaml"` → Direct execution
- **Without parameters**: `irm method with winforge.ps1` → CLI prompts via Read-Host

### 2. Encryption-Utility.ps1 (CLI Only)
- **With parameters**: `irm method with -Encrypt "config.yaml"` → Direct execution
- **Without parameters**: `irm method with Encryption-Utility.ps1` → CLI prompts via Read-Host

### 3. winforge-interactive.ps1 (GUI Launcher - New)
- **Always GUI**: Creates a user menu with the following options
  - Run Winforge (prompts using windows file picker to select a .yaml or .yml file)
  - Encrypt Configuration File
  - Decrypt Configuration File
- **Calls other scripts**: Executes winforge.ps1 and Encryption-Utility.ps1 with selected files

## Implementation

### Phase 1: Modify winforge.ps1
- Ensure Read-Host prompts when no ConfigPath provided (can support URL or local path)

### Phase 2: Modify Encryption-Utility.ps1
- Ensure Read-Host prompts when no ConfigPath provided (change name of FilePath parameter to ConfigPath to match)
- Ensure operation detection (Encrypt/Decrypt) prompt for choice when not detected.

### Phase 3: Create winforge-interactive.ps1
- Interactive Powershell menu using PSMenu module.
- Windows File picker for .yaml/.yml files
- Error handling with user-friendly messages

## User Experience

### CLI Users
```powershell
# Direct execution
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Graphixa/Winforge/refs/heads/main/winforge.ps1))) -ConfigPath "https://raw.githubusercontent.com/Graphixa/Winforge/refs/heads/main/winforge.yaml"
```

```powershell
# Interactive CLI
irm https://raw.githubusercontent.com/Graphixa/Winforge/refs/heads/main/winforge.ps1
# → Prompts: "Enter path or URL to configuration file"
```


### Winforge Interactive
```powershell
# Download and run GUI launcher
irm https://raw.githubusercontent.com/Graphixa/Winforge/refs/heads/main/winforge-interactive.ps1
# → Opens Windows Forms menu with file pickers
```


### Encryption Utility
```powershell
# CLI
irm https://raw.githubusercontent.com/Graphixa/Winforge/refs/heads/main/encryption-utility.ps1
# → Prompts: "Enter path to configuration file if no parameter is set"
```

```powershell
# Direct execution of Encryption
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Graphixa/Winforge/refs/heads/main/encryption-utility.ps1))) -ConfigPath "C:\winforge.yaml" -Encrypt 
# → Prompts: "Enter path to configuration file if no parameter is set for config file (supports local files only).
# → Prompts: "Enter prompts to select (Decrypt or Encrypt) if no parameter is set
```

```powershell
# Direct execution of Decryption
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Graphixa/Winforge/refs/heads/main/encryption-utility.ps1))) -ConfigPath "C:\winforge.yaml" -Decrypt
# → Prompts: "Enter path to configuration file if no parameter is set for config file (supports local files only).
# → Prompts: "Enter prompts to select (Decrypt or Encrypt) if no parameter is set
```

## Success Criteria

- [ ] All existing functionality preserved
- [ ] CLI and GUI separation complete
- [ ] No breaking changes for existing users
- [ ] Improved user experience for both CLI and GUI users 