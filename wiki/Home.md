# WinforgeX

WinforgeX is a powerful Windows configuration deployment tool that uses TOML-based configuration files to automate system setup and configuration. It's designed to be run remotely, allowing users to point to their own configuration files.

## Quick Start

### Remote Execution (Recommended)
```powershell
# Run directly from GitHub with your configuration
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Graphixa/WinforgeX/main/winforge.ps1))) -config "https://raw.githubusercontent.com/yourdomain/config.toml"
```

### Local Execution
```powershell
# Run locally with a configuration file
.\winforge.ps1 -config="path\to\config.toml"
```

## Requirements

- Windows PowerShell 5.1 or later
- Administrator privileges
- Internet connection (for remote execution and package management)
- PSToml module (automatically installed if missing)

## Documentation

1. **[Getting Started](Getting-Started)**
   - Installation Options
   - Basic Usage
   - Remote vs Local Execution

2. **[TOML Configuration Guide](TOML-Configuration-Guide)**
   - Configuration Format
   - Section Reference
   - Examples

3. **Configuration Sections**
   - [System Configuration](System-Configuration)
   - [Application Management](Application-Management)
   - [Network Configuration](Network-Configuration)
   - [Security Settings](Security-Settings)
   - [File Operations](File-Operations)
   - [Registry Modifications](Registry-Modifications)
   - [Office Configuration](Office-Configuration)
   - [Power Management](Power-Management)
   - [Privacy Settings](Privacy-Settings)
   - [Command Execution](Command-Execution)

4. **[Examples and Use Cases](Examples)**
   - Basic Configurations
   - Department Configurations
   - Enterprise Configurations

5. **[Troubleshooting](Troubleshooting)**
   - Common Issues
   - Error Messages
   - Logging

## Key Features

- **Remote Execution**: Run directly from GitHub or any web source
- **TOML Configuration**: Human-readable configuration format
- **Modular Design**: Configure only what you need
- **Secure**: Supports encrypted credentials and secure execution
- **Flexible**: Environment variable and network path support
- **Comprehensive**: Full Windows configuration capabilities
- **Logging**: Detailed operation logging
- **Error Handling**: Robust error management

## Security Features

- Encrypted configuration support
- Secure credential handling
- Admin privilege validation
- Execution policy management
- Network path security
- Logging of security changes

## Best Practices

1. **Remote Configuration**
   - Host configurations in a secure location
   - Use version control for configurations
   - Implement change management

2. **Security**
   - Use encrypted configurations for sensitive data
   - Validate configuration sources
   - Review logs regularly

3. **Deployment**
   - Test configurations in a safe environment
   - Use staging environments
   - Implement gradual rollouts

## Support

For issues, feature requests, or contributions:
1. Check the [Troubleshooting](Troubleshooting) guide
2. Review existing GitHub issues
3. Submit a new issue
4. Contact the development team

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details. 