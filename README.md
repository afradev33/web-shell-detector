# web-shell-detector
A lightweight, open-source Python tool for detecting web shells and malicious files on your own server. Scans PHP, ASP, and JSP files using 25+ pattern signatures with risk-level classification. Generates detailed JSON reports to help administrators respond quickly to potential threats.
# 🔍 Web Shell Detector

An open-source Python tool to help system administrators scan their own servers for uploaded web shells and malicious files.

---

## ⚠️ Legal & Ethical Disclaimer

> This tool is intended **exclusively** for use on servers and websites you own or have explicit written permission to scan.  
> Using this tool against systems without authorization is **illegal** and may violate computer crime laws in your jurisdiction.  
> The developer assumes no responsibility for any unlawful use of this tool.

---

## ✨ Features

-  Detects well-known web shells (c99, r57, b374k, WSO, and more)
-  Scans for **25+ malicious patterns** across PHP, ASP, and JSP files
-  Flags executable files (e.g. PHP) inside upload directories
-  Warns about suspicious filenames commonly used by attackers
-  Risk level classification: **High / Medium / Suspicious**
-  Exports a detailed JSON report
-  Supports PHP, ASP, ASPX, JSP, PHTML file types

---

##  Requirements

- Python 3.7 or later
- No external libraries required (Standard Library only)

---

##  Installation

```bash
git clone https://github.com/YOUR_USERNAME/web-shell-detector.git
cd web-shell-detector
```

No additional packages need to be installed.

---

##  Usage

### Basic scan
```bash
python3 shell_detector.py --path /var/www/html
```

### Save a JSON report
```bash
python3 shell_detector.py --path /var/www/html --report report.json
```

### Specify file extensions
```bash
python3 shell_detector.py --path /var/www --extensions php,asp,aspx
```

### Set maximum file size (in MB)
```bash
python3 shell_detector.py --path /var/www/html --max-size 10
```

### Full example
```bash
python3 shell_detector.py \
  --path /var/www/html \
  --extensions php,asp,aspx,jsp \
  --max-size 5 \
  --report /root/scan_report.json
```

---

##  Options

| Option | Shorthand | Description | Default |
|--------|-----------|-------------|---------|
| `--path` | `-p` | Path to the directory to scan | (required) |
| `--extensions` | `-e` | Comma-separated file extensions | `php,asp,aspx,jsp,phtml` |
| `--report` | `-r` | Path to save the JSON report | None |
| `--max-size` | — | Maximum file size in MB to scan | `5` |

---

##  Sample Output

```
============================================================
  Web Shell Detector
============================================================
  Path      : /var/www/html
  Extensions: .php, .asp, .aspx
  Date      : 2026-03-21 14:30:00
============================================================

📂 Found 342 files to scan...

────────────────────────────────────────────────────────────
  /var/www/html/uploads/image.php
   Risk  : High Risk 🔴
   Size  : 12.4 KB | MD5: a1b2c3d4e5f6...
   🔸 Executable file (.php) found inside an upload directory
   🔴 Line 3: eval+base64_decode — obfuscated code execution (1 match)

============================================================
  Scan Summary
============================================================
  Total files scanned  : 342
  Suspicious files     : 2
  High-risk files      : 1

  ⚠️  Warning: Review high-risk files immediately!
============================================================
```

---

##  Detected Patterns

### PHP
| Pattern | Description |
|---------|-------------|
| `eval(base64_decode(...))` | Executes Base64-encoded code |
| `eval($_POST[...])` | Executes code from user input |
| `system($_GET[...])` | Runs system commands |
| `shell_exec($_REQUEST[...])` | Executes shell commands |
| `move_uploaded_file` + POST | Malicious file upload handler |
| `preg_replace` + `/e` flag | Code execution via regex |
| Known shell names | c99, r57, b374k, WSO, etc. |

### ASP / ASPX
| Pattern | Description |
|---------|-------------|
| `WScript.Shell` | Windows command execution |
| `ADODB.Stream` | File read/write operations |
| `Execute(Request...)` | Dynamic code execution |

### JSP
| Pattern | Description |
|---------|-------------|
| `Runtime.getRuntime().exec()` | Java command execution |
| `ProcessBuilder` | System process creation |

---

## 📁 Project Structure

```
web-shell-detector/
│
├── shell_detector.py    # Main tool
├── README.md            # This file
└── LICENSE              # Project license
```

---

##  Contributing

Contributions are welcome!

1. Fork the repository
2. Create a new branch (`git checkout -b feature/new-pattern`)
3. Add new detection patterns or improvements
4. Open a Pull Request

---

##  License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

##  Contact

Found a bug or have a suggestion? Please open an [Issue](https://github.com/afradev33/web-shell-detector/issues) on GitHub.
