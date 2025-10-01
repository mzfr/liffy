[![GitSpo Mentions](https://gitspo.com/badges/mentions/mzfr/liffy?style=flat-square)](https://gitspo.com/mentions/mzfr/liffy)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/mzfr/liffy/graphs/commit-activity)
[![Rawsec's CyberSecurity Inventory](https://inventory.raw.pm/img/badges/Rawsec-inventoried-FF5050_flat.svg)](https://inventory.raw.pm/tools.html#Liffy)

[![Packaging status](https://repology.org/badge/vertical-allrepos/liffy.svg)](https://repology.org/project/liffy/versions)

<h1 align="center">
  <br>
  <a href="https://github.com/mzfr/liffy"><img src="Images/Liffy-logo.png" alt="liffy"></a>
  <br>
</h1>

<h4 align="center">Advanced LFI Exploitation Tool</h4>

![liffy in action](Images/liffy.png)

A powerful Python tool for Local File Inclusion (LFI) exploitation with advanced features including WAF bypass, encoding techniques, and comprehensive vulnerability detection.

Liffy v2.0 is the significantly enhanced version of [liffy](https://github.com/hvqzao/liffy) which was originally created by [rotlogix/liffy](https://github.com/rotlogix/liffy). This version includes modern features like Rich terminal output, YAML configuration, enhanced threading, and multiple advanced exploitation techniques.

Lot of new changes were vibe coded using claude.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Advanced Techniques](#advanced-techniques)
- [Examples](#examples)
- [Contribution](#contribution)
- [Credits](#credits)

## Features

### Core LFI Techniques

- **data://** - Code execution via data wrapper
- **expect://** - Code execution via expect wrapper
- **input://** - Code execution via input wrapper
- **filter://** - Arbitrary file reads via filter wrapper
- **/proc/self/environ** - Code execution in CGI mode
- **Apache access.log poisoning** - Log file exploitation
- **Linux auth.log SSH poisoning** - SSH log exploitation
- **Null Byte Poisoning** - Legacy PHP null byte attacks
- **ZIP wrapper exploitation** - ZIP file inclusion attacks

### Advanced Features

- **WAF Evasion** - Multiple bypass techniques for common WAFs
- **Advanced Encoding** - Double URL encoding, Unicode, case variations
- **POST Request Support** - Full POST method support with custom data
- **Custom Headers** - Configurable HTTP headers
- **User-Agent Rotation** - Randomized user agents to avoid detection
- **Rate Limiting** - Configurable request throttling
- **Multi-threading** - Enhanced thread pool management
- **Detection Mode** - Vulnerability scanning without exploitation
- **Rich Terminal Output** - Beautiful colored output with progress bars
- **YAML Configuration** - Persistent settings management

### Modern Enhancements

- **Enhanced Vulnerability Detection** - Advanced response analysis with confidence scoring
- **Thread Pool Management** - Optimized performance with adaptive threading
- **Configuration Management** - YAML-based settings with CLI overrides
- **Comprehensive Logging** - Detailed execution reports and progress tracking

## Installation

Make sure you are using **Python 3**. Liffy doesn't support Python 2.

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/mzfr/liffy
cd liffy

# Create virtual environment with uv
uv venv

# Activate virtual environment
source .venv/bin/activate  # On Linux/Mac
# .venv\Scripts\activate     # On Windows

# Install dependencies
uv pip install -r requirements.txt

# Run liffy
uv run python3 liffy.py --help
```

## Usage

### Basic Syntax

```bash
python3 liffy.py <URL> [OPTIONS]
```

### Command Line Options

```bash
usage: liffy.py [-h] [-d] [-i] [-e] [-f] [-p] [-a] [-ns] [-r] [--ssh]
                [-l LOCATION] [--cookies COOKIES] [-dt] [-t THREADS]
                [--detection] [--null-byte] [--zip] [--encoding]
                [--waf-bypass] [--method {GET,POST}] [--post-data POST_DATA]
                [--headers HEADERS] [--no-color] [--no-banner] [--config]
                [url]

positional arguments:
  url                   URL to test for LFI

Core Techniques:
  -d, --data            Use data:// technique
  -i, --input           Use input:// technique
  -e, --expect          Use expect:// technique
  -f, --filter          Use filter:// technique
  -p, --proc            Use /proc/self/environ technique
  -a, --access          Apache access logs technique
  --ssh                 SSH auth log poisoning
  -dt, --directorytraverse  Test for Directory Traversal
  --null-byte           Test for Null Byte Poisoning
  --zip                 Test for ZIP wrapper exploitation

Advanced Options:
  --encoding            Use advanced encoding/bypass techniques
  --waf-bypass          Use WAF evasion techniques
  --method {GET,POST}   HTTP method to use (default: GET)
  --post-data POST_DATA POST data (format: key=value&key2=value2)
  --headers HEADERS     Custom headers (format: Header1:Value1,Header2:Value2)
  --detection           Only perform LFI detection, no exploitation

General Options:
  -ns, --nostager       Execute payload directly, do not use stager
  -r, --relative        Use path traversal sequences for attack
  -l, --location LOCATION  Path to target file (access log, auth log, etc.)
  --cookies COOKIES     Session cookies for authentication
  -t, --threads THREADS Number of threads to use (default: 5)
  --no-color            Disable colored output
  --no-banner           Disable banner display
  --config              Create default YAML configuration file
```

## Configuration

### YAML Configuration

Create a configuration file for persistent settings:

```bash
python3 liffy.py --config
```

This creates `liffy_config.yaml` with default settings:

```yaml
# Liffy Configuration File
max_threads: 5
rate_limit_delay: 0.1
disable_colors: false
disable_banner: false
default_method: GET
user_agent_rotation: true
```

### Environment Variables

You can also use environment variables:

- `LIFFY_THREADS` - Number of threads
- `LIFFY_RATE_LIMIT` - Rate limit delay
- `LIFFY_NO_COLOR` - Disable colors (true/false)

## Advanced Techniques

### WAF Bypass Techniques

When `--waf-bypass` is enabled, liffy automatically applies multiple evasion techniques:

- **Comment Injection**: `/**/`, `#`, `;`
- **Protocol Confusion**: `file:///`, `pHp://`
- **Encoding Layering**: Multiple encoding combinations
- **Path Obfuscation**: `./`, `../`, null bytes

### Encoding Bypass Techniques

With `--encoding`, liffy applies advanced encoding methods:

- **Double URL Encoding**: `%252e%252e%252f`
- **Unicode Encoding**: `\u002e\u002e\u002f`
- **Mixed Case**: `..%2F`, `..%2f`
- **HTML Entity Encoding**: `&#46;&#46;&#47;`

### POST Request Support

```bash
# POST with form data
python3 liffy.py "http://target.com/lfi.php" -d --method POST --post-data "file=../../etc/passwd"

# POST with custom headers
python3 liffy.py "http://target.com/lfi.php" -d --method POST --headers "X-Forwarded-For:127.0.0.1,Authorization:Bearer token123"
```

## Examples

### Basic LFI Testing

#### Test with data:// wrapper

```bash
python3 liffy.py "http://example.com/page.php?file=" -d
```

#### Test with multiple techniques

```bash
python3 liffy.py "http://example.com/page.php?file=" -d -i -e -f
```

#### Detection mode only

```bash
python3 liffy.py "http://example.com/page.php?file=" --detection -d -i -e
```

### Advanced Usage

#### WAF bypass with encoding

```bash
python3 liffy.py "http://example.com/page.php?file=" -d --waf-bypass --encoding
```

#### Multi-threaded with rate limiting

```bash
python3 liffy.py "http://example.com/page.php?file=" -d -t 10 --config
```

#### POST request with custom headers

```bash
python3 liffy.py "http://example.com/upload.php" -d --method POST \
  --post-data "action=read&file=../../etc/passwd" \
  --headers "User-Agent:Mozilla/5.0,X-Forwarded-For:192.168.1.1"
```

### Log Poisoning

#### Apache access log poisoning

```bash
python3 liffy.py "http://example.com/page.php?file=" -a
```

#### SSH auth log poisoning

```bash
python3 liffy.py "http://example.com/page.php?file=" --ssh
```

#### Custom log location

```bash
python3 liffy.py "http://example.com/page.php?file=" -a -l "/var/log/apache2/access.log"
```

### Directory Traversal

#### Relative path traversal

```bash
python3 liffy.py "http://example.com/page.php?file=" -d -r
```

#### Directory traversal testing

```bash
python3 liffy.py "http://example.com/page.php?file=" -dt
```

### Special Techniques

#### Null byte poisoning (legacy PHP)

```bash
python3 liffy.py "http://example.com/page.php?file=" --null-byte
```

#### ZIP wrapper exploitation

```bash
python3 liffy.py "http://example.com/page.php?file=" --zip
```

#### Comprehensive scan with all techniques

```bash
python3 liffy.py "http://example.com/page.php?file=" \
  -d -i -e -f -p -a --ssh -dt --null-byte --zip \
  --encoding --waf-bypass --detection
```

### Authentication & Cookies

#### Using session cookies

```bash
python3 liffy.py "http://example.com/page.php?file=" -d \
  --cookies "PHPSESSID=abc123; auth_token=xyz789"
```

### Output Control

#### Disable colors and banner

```bash
python3 liffy.py "http://example.com/page.php?file=" -d --no-color --no-banner
```

## Default File Locations

The following default locations are used when no custom path is specified:

- **SSH auth.log**: `/var/log/auth.log`
- **Apache access.log**: `/var/log/apache2/access.log`
- **Alternative Apache log**: `/var/log/httpd/access_log`

## Contribution

We welcome contributions! Here's how you can help:

### Feature Suggestions

- New LFI exploitation techniques
- Additional WAF bypass methods
- Enhanced encoding techniques
- Payload optimization
- Detection improvements

### Bug Reports

- Report issues via GitHub Issues
- Include detailed reproduction steps
- Provide target environment details

### Pull Requests

- Fork the repository
- Create a feature branch
- Make your changes with tests
- Submit a pull request

Feel free to open an issue for any questions or suggestions!

## Vulnerability Detection

Liffy's detection mode provides comprehensive vulnerability analysis:

### Confidence Scoring

- **High Confidence (80-100%)**: Strong indicators like `/etc/passwd` content
- **Medium Confidence (50-79%)**: Partial file content or suspicious responses
- **Low Confidence (20-49%)**: Potential indicators requiring manual verification

### Detection Features

- **File Content Analysis**: Recognizes Linux, Windows, and PHP file patterns
- **Response Analysis**: HTTP status codes, content length, timing analysis
- **WAF Detection**: Identifies common WAF signatures
- **Evidence Collection**: Captures proof of vulnerability for reporting

### Sample Detection Output

```bash
[+] VULNERABILITY SUMMARY
==================================================
[1] Vulnerability Found
    Payload: ../../etc/passwd
    Confidence: 85%
    Evidence: Linux /etc/passwd file: root:
    Status Code: 200
    Content Length: 1547
```

## Troubleshooting

### Common Issues

#### WAF Blocking Requests

```bash
# Use WAF bypass techniques
python3 liffy.py "http://target.com/lfi.php" -d --waf-bypass

# Reduce thread count and increase delays
python3 liffy.py "http://target.com/lfi.php" -d -t 1
```

#### Rate Limiting Issues

```bash
# Increase delay in config file
max_threads: 2
rate_limit_delay: 1.0
```

### Debug Mode

For verbose output, you can modify the configuration:

```yaml
debug_mode: true
verbose_output: true
```

## Security Notice

**Liffy is designed for authorized security testing only.**

- Only use on systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Respect rate limits and avoid DoS conditions
- Be aware of legal implications in your jurisdiction

**The authors are not responsible for misuse of this tool.**

## Credits

### Original Inspiration

- Original [liffy](https://github.com/hvqzao/liffy) by hvqzao
- Initial concept from [rotlogix/liffy](https://github.com/rotlogix/liffy)

### Techniques and Research

- LFI exploitation techniques from various security research
- WAF bypass methods from public security resources
- PHP wrapper exploitation documentation

### Design and Assets

- Logo design from [renderforest](https://www.renderforest.com/)
- Terminal styling using [Rich](https://github.com/Textualize/rich) library

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
