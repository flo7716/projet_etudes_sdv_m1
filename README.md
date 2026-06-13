# README (Interactive CLI Guide)

## Overview

The **Swissknife Interactive CLI** provides a user-friendly menu-driven interface for the Pentest Toolbox instead of typing complex Docker and command-line arguments.

## Features

✅ **Interactive menus** - Select tools from a beautiful CLI menu  
✅ **Guided inputs** - Step-by-step prompts for all parameters  
✅ **Rich formatting** - Color-coded output and status indicators  
✅ **Error handling** - Clear error messages and recovery  
✅ **Tool information** - Built-in help for available tools  

## Installation

First, install the required dependencies:

```bash
# If running locally
pip install -r requirements.txt

# If running in Docker, dependencies are already included
```

## Usage

### Option 1: Using the Bash Wrapper (Recommended)

```bash
./run_cli.sh
```

This automatically:
- Detects your Docker setup
- Builds the service if needed
- Launches the interactive menu
- Cleans up when done

### Option 2: Using Docker Compose Directly

```bash
docker-compose run --rm api python -m app.cli_interactive
```

### Option 3: Running Locally (without Docker)

```bash
python -m app.cli_interactive
```

## Available Tools

### 🔍 NMAP - Network Scanning
- Performs network reconnaissance
- Port scanning and service detection
- OS fingerprinting

**Parameters:**
- Target host/IP
- Additional options (optional)

---

### 🔓 HYDRA - Brute-Force
- Password brute-forcing against services
- Supports multiple protocols

**Parameters:**
- Target host
- Username (default: root)
- Password list path (default: rockyou.txt)
- Additional options (optional)

---

### 🔑 JOHN - Password Cracking
- Cracks hashes from password files
- Supports multiple hash formats

**Parameters:**
- Hash file path
- Wordlist path
- Additional options (optional)

---

### 🕷️ NIKTO - Web Scanning
- Web server vulnerability scanning
- CGI scanning and outdated software detection

**Parameters:**
- Target host/URL
- Additional options (optional)

---

### 📁 GOBUSTER - Directory Scanning
- Directory and file brute-forcing
- Website structure mapping

**Parameters:**
- Target host/URL
- Wordlist path (default: common.txt)
- Additional options (optional)

---

### 🗄️ SQLMAP - SQL Injection
- SQL injection detection and exploitation
- Database dumping

**Parameters:**
- Target URL
- Additional options (optional)

---

### 🛜  AIRCRACK-NG - Wireless testing
- Wireless capture analysis and cracking support
- Useful for auditing captured handshakes

**Parameters:**
- Capture file or handshake path
- Additional options (optional)

---

### 🧪 NUCLEI - Vulnerability scanning
- Fast, template-based vulnerability discovery
- Great for web and infrastructure checks

**Parameters:**
- Target URL or host
- Additional options (optional)

---

### 🛡️ MSFVENOM - Payload generation
- Generates payloads for various platforms
- Supports multiple encoding techniques

**Parameters:**
- Payload type
- LHOST (listener host)
- LPORT (listener port)
- Additional options (optional such as RHOSTS, RPORTS, etc.)

---

### 🔎 SEARCHSPLOIT - Vulnerability Search
- Search for exploits in the Exploit Database
- Quick access to exploit information

**Parameters:**
- Search query (e.g., software name, CVE ID)
- Additional options (optional)

---

### 🕷️ FFUF - Web Fuzzing
- Fast web fuzzer for directory and file discovery
- Customizable request patterns and response matching

**Parameters:**
- Target URL (with FUZZ placeholder)
- Wordlist path
- Additional options (optional)

---

### 🛡️ CLAMSCAN - Antivirus Scanning
- Scans files for malware and viruses
- Supports multiple file formats

**Parameters:**
- File or directory path to scan
- Additional options (optional)

---

### 🔓 SSLYZE - SSL/TLS scanning
- Analyzes SSL/TLS configurations of servers
- Checks for vulnerabilities and misconfigurations

**Parameters:**
- Target host/URL
- Additional options (optional)

---

### 🦈 TSHARK - Packet inspection
- Network packet capture and analysis
- Supports various protocols and filters
**Parameters:**
- Network interface to capture on
- Capture duration (optional)
- Additional options (optional)

---

### 📊 PIPELINE - Full Pentest Pipeline
- Run multiple tests in sequence
- Generate comprehensive PDF report

**Parameters:**
- Target host/URL
- Tests to run (select multiple)
- Output PDF filename
- Copy to host mount (optional)

---

## Interactive Menu Example

```
╔════════════════════════════════════════╗
║    PENTEST TOOLBOX - Interactive CLI   ║
║     Security Testing Framework         ║
╚════════════════════════════════════════╝

? Select a tool to run:
  → 🔍 NMAP - Network Scanning
    🔓 HYDRA - Brute-Force
    🔑 JOHN - Password Cracking
    🕷️  NIKTO - Web Scanning
    📁 GOBUSTER - Directory Scanning
    🗄️  SQLMAP - SQL Injection
    🛜 AIRCRACK-NG - Wireless testing
    🧪 NUCLEI - Vulnerability scanning
    🛡️ MSFVENOM - Payload generation
    🔎 SEARCHSPLOIT - Vulnerability Search
    🕷️  FFUF - Web Fuzzing
    📊 PIPELINE - Run Full Pipeline
    ℹ️  Information
    ❌ Exit
```

## Workflow Example

### 1. Launching the CLI
```bash
./run_cli.sh
```

### 2. Selecting a Tool
Use arrow keys to navigate, press Enter to select

### 3. Entering Parameters
Follow the prompts and enter required information

### 4. Execution
The tool runs and displays results in real-time

### 5. Continue or Exit
Choose to run another tool or exit

## Comparison: Old vs New

### Before (CLI Arguments)
```bash
docker-compose run api python -m app.main nmap 192.168.1.1 --options "-sV -p 1-65535"
```

### After (Interactive)
```bash
./run_cli.sh
# Just follow the menu prompts!
```

## Troubleshooting

### "questionary not found"
Make sure dependencies are installed:
```bash
pip install -r requirements.txt
```

### "Docker service not running"
Ensure Docker is started:
```bash
docker-compose up -d
```

### "Permission denied" on run_cli.sh
Make the script executable:
```bash
chmod +x run_cli.sh
```

### Results not displaying correctly
Make sure your terminal supports ANSI colors (most modern terminals do).

## Integration with Existing CLI

The interactive CLI **coexists** with the existing argparse CLI:

- **Interactive:** `./run_cli.sh` or `python -m app.cli_interactive`
- **Command-line:** `docker-compose run api python -m app.main nmap 192.168.1.1`
- **Direct Python:** `python app/main.py hydra example.com --user admin`

Choose whichever fits your workflow!

## Tips

✨ **Pro Tips:**

1. **Batch Testing:** Use the PIPELINE tool to run multiple tests and generate a complete report
2. **Save Output:** Redirect output to files for record-keeping
3. **Defaults:** Most fields have sensible defaults - just press Enter to use them
4. **Multiple Runs:** You can run multiple tools in one session without restarting
5. **Quick Exit:** Press Ctrl+C anytime to exit (changes are saved)

## Advanced Usage

### Custom Wordlists
When prompted for wordlist paths, enter any valid path:
```
? Wordlist path: /custom/path/to/wordlist.txt
```

### Additional Options
For tools with "Additional options" fields, enter raw tool arguments:
```
? Additional nmap options: -sS -sV -p 80,443,8080
```

### Pipeline with Selected Tests
Create focused penetration testing workflows:
1. Select PIPELINE
2. Choose only relevant tests (e.g., just NMAP + NIKTO)
3. Specify target
4. Get targeted PDF report

## Support

For issues or feature requests:
1. Check the main application documentation
2. Review tool-specific documentation
3. Check error messages in the console output
