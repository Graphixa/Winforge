# WinforgeX Documentation

WinforgeX is a powerful Windows configuration deployment tool that uses TOML-based configuration files to automate system setup and configuration.

## Table of Contents

1. [Getting Started](getting-started.md)
   - Installation
   - Requirements
   - Basic Usage

2. [Configuration Guide](configuration-guide.md)
   - TOML Format Overview
   - Configuration Sections
   - Environment Variables
   - Validation Rules

3. [Feature Documentation](features/README.md)
   - [System Configuration](features/system-configuration.md)
   - [Application Management](features/application-management.md)
   - [Network Configuration](features/network-configuration.md)
   - [Security Settings](features/security-settings.md)
   - [File Operations](features/file-operations.md)
   - [Registry Modifications](features/registry-modifications.md)
   - [Office Configuration](features/office-configuration.md)
   - [Power Management](features/power-management.md)
   - [Privacy Settings](features/privacy-settings.md)
   - [Command Execution](features/command-execution.md)

4. [Examples](examples/README.md)
   - [Basic Configuration](examples/basic-config.md)
   - [Full Configuration](examples/full-config.md)
   - [Common Scenarios](examples/common-scenarios.md)

5. [Troubleshooting](troubleshooting.md)
   - Common Issues
   - Error Messages
   - Logging
   - Debug Mode

## Quick Start

```powershell
# Install required module
Install-Module -Name PSToml -Force -Scope CurrentUser

# Run WinforgeX with a configuration file
.\winforge.ps1 -ConfigPath "config.toml"
```

## Features

- **TOML Configuration**: Human-readable configuration format
- **Modular Design**: Configure only what you need
- **Secure**: Supports encrypted credentials
- **Flexible**: Environment variable support
- **Powerful**: Comprehensive Windows configuration capabilities
- **Logging**: Detailed logging of all operations
- **Error Handling**: Robust error handling and reporting

## Security

- Supports encrypted configuration files
- Secure credential handling
- Admin privilege validation
- Logging of security-related changes

## Support

For issues, feature requests, or contributions, please visit our repository.

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details. 