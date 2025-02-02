# Winforge

Winforge is a powerful Windows configuration deployment tool that uses TOML-based configuration files to automate system setup and configuration. Whether you're a developer setting up your coding environment, a power user customizing your home setup, an IT professional managing multiple machines, or anyone looking to automate Windows configuration, Winforge makes it easy to deploy and maintain your perfect Windows setup.

## Quick Start

### Remote Execution (Recommended)
```powershell
# Run directly from GitHub with your configuration
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Graphixa/Winforge/main/winforge.ps1))) -config "https://raw.githubusercontent.com/yourdomain/config.toml"
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

1. **[Getting Started](/docs/Getting-Started.md)**
   - Quick setup guide
   - Basic usage
   - Remote vs Local execution
   - First configuration

2. **[TOML Configuration Guide](/docs/Configuration-Guide.md)**
   - Complete configuration reference
   - All available options
   - Configuration examples
   - Best practices

3. **Common Use Cases**
   - [Developer Setup](/examples/Developer-Configuration.toml) - Development environments and tools
   - [Home Lab](/examples/Home-Lab-Configuration.toml) - Personal server and network configuration
   - [Gaming Setup](/examples/Gaming-Configuration.toml) - Gaming optimizations and tools
   - [Work Environment](/examples/Work-Environment-Configuration.toml) - Professional workspace configuration

4. **[Troubleshooting Guide](/docs/Troubleshooting.md)**
   - Common issues and solutions
   - Error messages explained
   - Configuration validation
   - Logging and debugging

## Key Features

- **Flexible Deployment**: Run directly from GitHub, network share, or locally
- **Human-Readable Config**: Simple TOML configuration format
- **Modular Design**: Use only the features you need
- **Secure**: Built-in security features and encrypted credentials
- **Versatile**: From simple tweaks to complete system setup
- **Powerful**: Comprehensive Windows configuration capabilities
- **Detailed Logging**: Track all changes with detailed logs
- **Error Handling**: Robust error management and recovery

## Configuration Sections

Winforge supports extensive configuration options through these main sections:

- **System Settings**
  - Computer name and locale
  - Windows features and services
  - System preferences and behavior

- **Applications**
  - Software installation (Winget/Chocolatey)
  - Application removal
  - Bloatware cleanup

- **User Experience**
  - Theme and appearance
  - Taskbar and Start menu
  - File Explorer settings
  - Desktop preferences

- **Security**
  - Windows Defender
  - BitLocker encryption
  - User Account Control
  - Privacy settings

- **Network**
  - Network drives
  - Sharing settings
  - Network discovery

- **Power Management**
  - Power plans
  - Sleep settings
  - Fast startup

See the [TOML Configuration Guide](TOML-Configuration-Guide) for complete details.

## Security Features

- **Encrypted Configurations**: Protect sensitive data
- **Secure Credentials**: Safe credential handling
- **Admin Validation**: Proper privilege management
- **Execution Policy**: Controlled script execution
- **Network Security**: Secure network operations
- **Audit Logging**: Track all security changes

## Best Practices

1. **Configuration Management**
   - Keep configurations in version control
   - Document your changes
   - Use modular configurations
   - Test before deployment

2. **Security**
   - Encrypt sensitive configurations
   - Use secure configuration sources
   - Review logs regularly
   - Follow least privilege principle

3. **Deployment**
   - Test in a safe environment first
   - Use staging when possible
   - Implement gradually
   - Backup before major changes

## Support

Need help? Here's how to get support:

1. Check the [Troubleshooting Guide](Troubleshooting)
2. Search [existing issues](https://github.com/Graphixa/Winforge/issues)
3. Review [examples](Examples) and [documentation](TOML-Configuration-Guide)
4. [Submit a new issue](https://github.com/Graphixa/Winforge/issues/new)

## Contributing

Contributions are welcome! Whether you're fixing bugs, adding features, or improving documentation, check out our [contribution guidelines](CONTRIBUTING.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 