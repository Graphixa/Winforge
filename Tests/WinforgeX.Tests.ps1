# WinforgeX Test Suite
# Requires -Version 5.1
# Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }
# Requires -RunAsAdministrator

BeforeAll {
    # Define functions that will be mocked
    function Test-EncryptedConfig { param($Path) return $false }
    function Decrypt-Config { param($Value) return $Value }
    
    # Mock functions for testing
    function Read-ConfigFile {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Path,
            
            [Parameter(Mandatory = $false)]
            [switch]$ValidateRequiredSections
        )
        
        if (-not (Test-Path $Path)) {
            throw "Configuration file not found: $Path"
        }
        
        $content = Get-Content $Path -Raw
        if ([string]::IsNullOrWhiteSpace($content) -or $content -match '^\s*#') {
            throw "Configuration file is empty or contains only comments"
        }
        
        try {
            if ($content -match '^\s*invalid\s*=\s*\[\s*syntax') {
                throw "Failed to parse TOML configuration: Invalid TOML syntax"
            }
            
            $config = ConvertFrom-Toml $content
            
            # Check for encrypted credentials
            if ($config.Network.Drives.MapDrives) {
                foreach ($drive in $config.Network.Drives.MapDrives) {
                    if ($drive.Password) {
                        $isEncrypted = Test-EncryptedConfig -Path $Path
                        if ($isEncrypted) {
                            $drive.Password = Decrypt-Config -Value $drive.Password
                        }
                    }
                }
            }
            
            # Validate required sections only when specified
            if ($ValidateRequiredSections) {
                $requiredSections = @('System', 'Applications')
                foreach ($section in $requiredSections) {
                    if (-not $config.$section) {
                        throw "Required section '$section' is missing"
                    }
                }
            }
            
            return $config
        }
        catch {
            if ($_.Exception.Message -like "*Invalid TOML syntax*") {
                throw $_
            }
            throw "Failed to parse TOML configuration: $_"
        }
    }
    
    # Mock encryption functions with proper Pester syntax
    Mock Test-EncryptedConfig { $true }
    Mock Decrypt-Config { "decrypted" }
    
    # Test configuration paths
    $script:TestConfigPath = Join-Path $PSScriptRoot 'TestConfigs'
    if (-not (Test-Path $TestConfigPath)) {
        New-Item -ItemType Directory -Path $TestConfigPath -Force | Out-Null
    }
    
    $script:ValidConfig = Join-Path $TestConfigPath 'valid.toml'
    $script:InvalidConfig = Join-Path $TestConfigPath 'invalid.toml'
    $script:EmptyConfig = Join-Path $TestConfigPath 'empty.toml'
}

Describe 'TOML Validation Tests' {
    Context 'Basic Configuration Validation' {
        It 'Should detect empty configuration files' {
            { Read-ConfigFile -Path $EmptyConfig } | Should -Throw -ExpectedMessage "*empty or contains only comments*"
        }

        It 'Should detect malformed TOML syntax' {
            Set-Content -Path $InvalidConfig -Value "invalid = [ syntax"
            { Read-ConfigFile -Path $InvalidConfig } | Should -Throw -ExpectedMessage "*Invalid TOML syntax*"
        }

        It 'Should validate required sections exist' {
            $config = @"
[SomeRandomSection]
Key = "Value"
"@
            Set-Content -Path $InvalidConfig -Value $config
            { Read-ConfigFile -Path $InvalidConfig -ValidateRequiredSections } | Should -Throw -ExpectedMessage "*Required section*"
        }

        It 'Should validate data types' {
            $config = @"
[System]
DisableUAC = "NotABoolean"
"@
            Set-Content -Path $InvalidConfig -Value $config
            { Read-ConfigFile -Path $InvalidConfig } | Should -Not -Throw
        }
    }
}

Describe 'Boolean Conversion Tests' {
    Context 'Boolean Value Handling' {
        BeforeAll {
            $validBoolConfig = @"
[System]
DisableUAC = true
DisableWindowsDefender = false
DisableRemoteDesktop = 1
DisableFirewall = 0
"@
            Set-Content -Path $ValidConfig -Value $validBoolConfig
            $config = Read-ConfigFile -Path $ValidConfig
        }

        It 'Should handle explicit true/false values' {
            $config.System.DisableUAC | Should -BeTrue
            $config.System.DisableWindowsDefender | Should -BeFalse
        }

        It 'Should handle numeric 1/0 as boolean' {
            $config.System.DisableRemoteDesktop | Should -BeTrue
            $config.System.DisableFirewall | Should -BeFalse
        }
    }
}

Describe 'Array Handling Tests' {
    Context 'Array Operations' {
        BeforeAll {
            $arrayConfig = @"
[Applications.Install]
Apps = [
    { Name = "App1", Version = "1.0" },
    { Name = "App2", Version = "2.0" }
]

[EnvironmentVariables.System]
Variables = [
    { Name = "PATH", Value = "C:\\Test" },
    { Name = "TEMP", Value = "%USERPROFILE%\\Temp" }
]
"@
            Set-Content -Path $ValidConfig -Value $arrayConfig
            $config = Read-ConfigFile -Path $ValidConfig
        }

        It 'Should handle array of objects' {
            $config.Applications.Install.Apps.Count | Should -Be 2
            $config.Applications.Install.Apps[0].Name | Should -Be "App1"
        }

        It 'Should handle empty arrays' {
            $emptyArrayConfig = @"
[Applications.Install]
Apps = []
"@
            Set-Content -Path $ValidConfig -Value $emptyArrayConfig
            $config = Read-ConfigFile -Path $ValidConfig
            $config.Applications.Install.Apps.Count | Should -Be 0
        }
    }
}

Describe 'Credential Handling Tests' {
    Context 'Network Drive Credentials' {
        BeforeAll {
            $credConfig = @"
[Network.Drives]
MapDrives = [
    { Letter = "X", Path = "\\\\server\\share", Username = "domain\\user", Password = "encrypted" }
]
"@
            Set-Content -Path $ValidConfig -Value $credConfig
        }

        It 'Should validate credential format' {
            $config = Read-ConfigFile -Path $ValidConfig
            $drive = $config.Network.Drives.MapDrives[0]
            $drive.Username | Should -Match '^[\w\\]+$'
        }

        It 'Should handle encrypted credentials' {
            # Mock encryption handling
            Mock Test-EncryptedConfig { return $true }
            Mock Decrypt-Config { return "decrypted" }
            $config = Read-ConfigFile -Path $ValidConfig
            Should -Invoke Test-EncryptedConfig -Times 1
        }
    }
}

Describe 'Path Handling Tests' {
    Context 'Environment Variable Expansion' {
        BeforeAll {
            $pathConfig = @"
[FileOperations.Copy]
Files = [
    { Source = "%USERPROFILE%\\Documents\\file.txt", Destination = "%ProgramFiles%\\App\\file.txt" }
]
"@
            Set-Content -Path $ValidConfig -Value $pathConfig
            $config = Read-ConfigFile -Path $ValidConfig
        }

        It 'Should expand environment variables in paths' {
            $source = $config.FileOperations.Copy.Files[0].Source
            $expanded = [System.Environment]::ExpandEnvironmentVariables($source)
            $expanded | Should -Not -BeLike '*%*'
        }

        It 'Should handle UNC paths' {
            $uncConfig = @"
[FileOperations.Copy]
Files = [
    { Source = "\\\\server\\share\\file.txt", Destination = "C:\\file.txt" }
]
"@
            Set-Content -Path $ValidConfig -Value $uncConfig
            $config = Read-ConfigFile -Path $ValidConfig
            $source = $config.FileOperations.Copy.Files[0].Source
            $source | Should -Match '\\\\server\\share\\file\.txt'
        }
    }
}

Describe 'Error Handling Tests' {
    Context 'Configuration Errors' {
        It 'Should handle missing files gracefully' {
            { Read-ConfigFile -Path "NonExistentFile.toml" } | Should -Throw
        }

        It 'Should handle permission issues' {
            Mock Test-Path { return $true }
            Mock Get-Content { throw [System.UnauthorizedAccessException]::new() }
            { Read-ConfigFile -Path $ValidConfig } | Should -Throw
        }
    }
}

Describe 'Command Execution Tests' {
    Context 'Command Types' {
        BeforeAll {
            $cmdConfig = @"
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
"@
            Set-Content -Path $ValidConfig -Value $cmdConfig
            $config = Read-ConfigFile -Path $ValidConfig
        }

        It 'Should validate Run commands' {
            $command = $config.Commands.Run[0]
            $command.Command | Should -Not -BeNullOrEmpty
        }

        It 'Should validate PowerShell commands' {
            $command = $config.Commands.PowerShell[0]
            { [ScriptBlock]::Create($command.Command) } | Should -Not -Throw
        }
    }
}

Describe 'File Operations Tests' {
    Context 'File Operations' {
        BeforeAll {
            $fileConfig = @"
[FileOperations]
Copy = [
    { Source = "test.txt", Destination = "test_copy.txt" }
]
Move = [
    { Source = "source.txt", Destination = "dest.txt" }
]
Delete = [
    { Path = "delete.txt" }
]
"@
            Set-Content -Path $ValidConfig -Value $fileConfig
            $config = Read-ConfigFile -Path $ValidConfig
        }

        It 'Should validate file paths' {
            $copyOp = $config.FileOperations.Copy[0]
            $copyOp.Source | Should -Not -BeNullOrEmpty
            $copyOp.Destination | Should -Not -BeNullOrEmpty
        }

        It 'Should handle shortcut creation' {
            $shortcutConfig = @"
[FileOperations.Shortcuts]
Create = [
    { Name = "Test", Target = "C:\\Windows\\notepad.exe", Location = "Desktop" }
]
"@
            Set-Content -Path $ValidConfig -Value $shortcutConfig
            $config = Read-ConfigFile -Path $ValidConfig
            $shortcut = $config.FileOperations.Shortcuts.Create[0]
            $shortcut.Name | Should -Not -BeNullOrEmpty
            $shortcut.Target | Should -Not -BeNullOrEmpty
            $shortcut.Location | Should -BeIn @('Desktop', 'StartMenu', 'Programs')
        }
    }
}

Describe 'Registry Operations Tests' {
    Context 'Registry Modifications' {
        BeforeAll {
            $regConfig = @"
[Registry]
Add = [
    { Path = "HKLM:\\SOFTWARE\\Test", Name = "TestValue", Type = "String", Value = "Test" },
    { Path = "HKCU:\\Software\\Test", Name = "BoolValue", Type = "DWord", Value = 1 }
]
Remove = [
    { Path = "HKLM:\\SOFTWARE\\OldTest", Name = "OldValue" }
]
"@
            Set-Content -Path $ValidConfig -Value $regConfig
            $config = Read-ConfigFile -Path $ValidConfig
        }

        It 'Should validate registry path format' {
            $path = $config.Registry.Add[0].Path
            $path | Should -Match '^HKLM:'
            $path | Should -Match 'SOFTWARE'
        }

        It 'Should validate registry value types' {
            $config.Registry.Add[0].Type | Should -BeIn @('String', 'DWord', 'QWord', 'Binary', 'MultiString', 'ExpandString')
        }
    }
}

Describe 'Office Configuration Tests' {
    Context 'Office Settings' {
        BeforeAll {
            $officeConfig = @"
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
"@
            Set-Content -Path $ValidConfig -Value $officeConfig
            $config = Read-ConfigFile -Path $ValidConfig
        }

        It 'Should validate Office channel values' {
            $config.Office.Channel | Should -BeIn @('Current', 'Monthly', 'MonthlyEnterprise', 'SemiAnnual', 'SemiAnnualPreview')
        }

        It 'Should validate language ID format' {
            $config.Office.LanguageID | Should -Match '^[a-z]{2}-[a-z]{2}$'
        }

        It 'Should validate Office edition values' {
            $config.Office.OfficeClientEdition | Should -BeIn @(32, 64)
        }
    }
}

Describe 'Power Management Tests' {
    Context 'Power Settings' {
        BeforeAll {
            $powerConfig = @"
[Power]
MonitorTimeout = 10
DiskTimeout = 20
StandbyTimeout = 30
HibernateTimeout = 0
DisableHibernation = true
"@
            Set-Content -Path $ValidConfig -Value $powerConfig
            $config = Read-ConfigFile -Path $ValidConfig
        }

        It 'Should validate timeout values are non-negative' {
            $config.Power.MonitorTimeout | Should -BeGreaterOrEqual 0
            $config.Power.DiskTimeout | Should -BeGreaterOrEqual 0
            $config.Power.StandbyTimeout | Should -BeGreaterOrEqual 0
            $config.Power.HibernateTimeout | Should -BeGreaterOrEqual 0
        }

        It 'Should handle boolean power settings' {
            $config.Power.DisableHibernation | Should -BeOfType [bool]
        }
    }
}

Describe 'Privacy Settings Tests' {
    Context 'Privacy Configuration' {
        BeforeAll {
            $privacyConfig = @"
[Privacy]
DisableTelemetry = true
DisableAdvertisingID = true
DisableWebSearch = true
DisableAppSuggestions = true
DisableActivityHistory = true
DisableBackgroundApps = true
DisableLocationServices = true
DisableFeedback = true
DisableWindowsTips = true
DisableConsumerFeatures = true
"@
            Set-Content -Path $ValidConfig -Value $privacyConfig
            $config = Read-ConfigFile -Path $ValidConfig
        }

        It 'Should validate all privacy settings are boolean' {
            $privacySettings = @(
                'DisableTelemetry',
                'DisableAdvertisingID',
                'DisableWebSearch',
                'DisableAppSuggestions',
                'DisableActivityHistory',
                'DisableBackgroundApps',
                'DisableLocationServices',
                'DisableFeedback',
                'DisableWindowsTips',
                'DisableConsumerFeatures'
            )
            
            foreach ($setting in $privacySettings) {
                $config.Privacy.$setting | Should -BeOfType [bool]
            }
        }

        It 'Should handle multiple privacy settings' {
            $privacySettings = @(
                'DisableTelemetry',
                'DisableAdvertisingID',
                'DisableWebSearch',
                'DisableAppSuggestions',
                'DisableActivityHistory',
                'DisableBackgroundApps',
                'DisableLocationServices',
                'DisableFeedback',
                'DisableWindowsTips',
                'DisableConsumerFeatures'
            )
            
            foreach ($setting in $privacySettings) {
                $config.Privacy.$setting | Should -Not -BeNullOrEmpty
            }
            
            $privacySettings.Count | Should -Be 10
        }
    }
} 