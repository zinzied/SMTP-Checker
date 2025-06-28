# Enhanced SMTP Checker v2.0

A powerful Python application with a modern GUI for testing SMTP server credentials. This tool provides an enhanced interface for validating email and password combinations against various SMTP servers with advanced configuration options and comprehensive logging.

## Features

- **Modern GUI Interface**: Built with tkinter featuring a clean, professional design
- **Multi-threaded Processing**: Configurable thread count (1-1000) for optimal performance
- **Advanced Configuration**: Customizable SMTP hosts, ports, timeouts, and test settings
- **Real-time Progress Tracking**: Live progress bar and statistics display
- **Comprehensive Logging**: Detailed activity logs with multiple log levels
- **Results Export**: Automatic saving to multiple output formats
- **SSL/TLS Support**: Handles both secure (465) and standard (587, 25) SMTP ports
- **Smart Host Detection**: Automatic SMTP server discovery with caching
- **Error Handling**: Robust error handling and recovery mechanisms
- **Configuration Management**: Persistent settings with JSON configuration

## Requirements

- Python 3.6 or higher
- tkinter (usually included with Python)
- requests library

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/zinzied/SMTP-Checker.git
   cd SMTP-Checker
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Launch the application:**
   ```bash
   python smtp.py
   ```

2. **Configure settings:**
   - Select your combo file (email:password format, one per line)
   - Set the number of threads (default: 50)
   - Access advanced settings for custom SMTP hosts, ports, and timeouts

3. **Start checking:**
   - Click "Start Checking" to begin the validation process
   - Monitor real-time progress and statistics
   - View detailed logs in the activity window

4. **Review results:**
   - Valid credentials are saved to `cracked_smtps.txt` (detailed format)
   - Mail access credentials are saved to `cracked_Mailaccess.txt` (simple format)
   - Check the activity log for detailed processing information

## Configuration

The application uses `smtp_config.json` for persistent settings:

- **SMTP Hosts**: List of SMTP server prefixes to test
- **SMTP Ports**: Ports to test (587, 465, 25 by default)
- **Connection Timeout**: Timeout in seconds for connection attempts
- **Test Email**: Email address for testing mail sending capability
- **Thread Settings**: Default and maximum thread counts
- **Logging**: Log level and output preferences

## Output Files

- `cracked_smtps.txt`: Detailed results with timestamps, hosts, ports, and credentials
- `cracked_Mailaccess.txt`: Simple email:password format for easy import
- `smtp_checker.log`: Comprehensive application logs
- `smtp_config.json`: Application configuration settings

## Combo File Format

The input file should contain email:password combinations, one per line:
```
user@example.com:password123
test@domain.com:mypassword
admin@site.org:secretpass
```

## Legal Notice

⚠️ **IMPORTANT**: This application is intended for educational and authorized security testing purposes only.

- Only use this tool on systems you own or have explicit permission to test
- Unauthorized access to email accounts or SMTP servers is illegal
- Users are responsible for complying with all applicable laws and regulations
- The developers assume no liability for misuse of this software

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Zied Boughdir** - [GitHub](https://github.com/zinzied)

Enhanced with AI assistance for improved functionality and user experience.

---

[![Buy Me A Coffee](https://github.com/zinzied/Website-login-checker/assets/10098794/24f9935f-3637-4607-8980-06124c2d0225)](https://www.buymeacoffee.com/Zied)
