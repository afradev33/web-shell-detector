#!/usr/bin/env python3
"""
==================================================
 Web Shell Detector
 Scan your own server for malicious web shells
==================================================
Usage:
    python3 shell_detector.py --path /var/www/html
    python3 shell_detector.py --path /var/www/html --report report.json
    python3 shell_detector.py --path /var/www/html --extensions php,asp,aspx,jsp

DISCLAIMER:
    This tool is intended exclusively for use on servers you own
    or have explicit written permission to scan. Unauthorized use
    is illegal and unethical.
"""

import os
import re
import sys
import json
import hashlib
import argparse
import datetime
from pathlib import Path
from typing import List, Dict, Tuple

# =============================================
# Known Malicious Patterns
# =============================================
SHELL_PATTERNS = {
    "PHP": [
        # Obfuscated code execution
        (r"eval\s*\(\s*base64_decode\s*\(", "eval+base64_decode — obfuscated code execution"),
        (r"eval\s*\(\s*gzinflate\s*\(", "eval+gzinflate — compressed code execution"),
        (r"eval\s*\(\s*str_rot13\s*\(", "eval+str_rot13 — ROT13 encoded execution"),
        (r"eval\s*\(\s*gzuncompress\s*\(", "eval+gzuncompress — compressed payload"),
        (r"eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)", "eval with user-supplied input"),
        (r"assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)", "assert with user-supplied input"),
        (r"preg_replace\s*\(.+/e['\"]", "preg_replace with /e flag — code execution via regex"),
        # System command execution
        (r"\bsystem\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)", "system() with user input"),
        (r"\bexec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)", "exec() with user input"),
        (r"\bshell_exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)", "shell_exec() with user input"),
        (r"\bpassthru\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)", "passthru() with user input"),
        (r"\bpopen\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)", "popen() with user input"),
        (r"`\s*\$_(POST|GET|REQUEST|COOKIE)", "backtick execution with user input"),
        # Malicious file upload
        (r"move_uploaded_file.+\$_(POST|GET|FILES)", "move_uploaded_file with user-controlled path"),
        (r"file_put_contents.+\$_(POST|GET|REQUEST)", "file_put_contents with user input"),
        # Known shell signatures
        (r"c99shell|r57shell|b374k|wso\s*shell|c100\s*shell", "known web shell name detected"),
        (r"FilesMan|WSO\s*[0-9]|b374k\s*shell", "known shell signature"),
        (r"\$_F=__FILE__;\$_X=", "compressed shell pattern"),
        (r"@?\$_(GET|POST|REQUEST|COOKIE)\[.{0,20}\]\s*\(\s*@?\$_(GET|POST|REQUEST|COOKIE)", "dynamic function call from user input"),
        # Chained obfuscation
        (r"base64_decode\s*\(\s*str_replace", "base64_decode chained with str_replace"),
        (r"gzinflate\s*\(\s*base64_decode", "gzinflate+base64_decode chain"),
        (r"str_rot13\s*\(\s*base64_decode", "rot13+base64 obfuscation chain"),
        (r"\$[a-zA-Z_]+\s*=\s*str_split\s*\(.+;\s*\$[a-zA-Z_]+\s*\(\s*\$", "dynamic string-split function call"),
        # Session-based backdoor
        (r'session_start.+\$_SESSION\[.+\]\s*=\s*\$_(GET|POST)', "session variable set from user input"),
    ],
    "ASP": [
        (r"Server\.CreateObject\s*\(\s*[\"']WScript\.Shell[\"']\)", "WScript.Shell — command execution"),
        (r"\.Run\s*\(\s*Request\.", "Run() called with Request data"),
        (r"Execute\s*\(\s*Request\.", "Execute() with Request input"),
        (r"eval\s*\(\s*Request\.", "eval with Request input"),
        (r"CreateObject\s*\(\s*[\"']ADODB\.Stream[\"']\)", "ADODB.Stream — file read/write"),
    ],
    "JSP": [
        (r"Runtime\.getRuntime\(\)\.exec\s*\(", "Runtime.exec() — command execution"),
        (r"request\.getParameter.+Runtime", "Runtime called with request parameter"),
        (r"ProcessBuilder", "ProcessBuilder — system process creation"),
    ],
    "General": [
        (r"<\?php\s+@?\$\w+\s*=\s*@?(chr|base64_decode|gzinflate)", "obfuscated PHP code"),
        (r"(?i)(union\s+select|drop\s+table|insert\s+into).{0,100}(POST|GET|REQUEST)", "possible SQL injection payload"),
    ]
}

# Executable extensions that should not be in upload directories
SUSPICIOUS_EXTENSIONS_IN_UPLOADS = [
    '.php', '.php3', '.php4', '.php5', '.phtml',
    '.asp', '.aspx', '.jsp', '.jspx'
]

# Suspicious filenames commonly used by attackers
SUSPICIOUS_FILENAMES = [
    'shell', 'cmd', 'c99', 'r57', 'b374k', 'wso', 'bypass',
    'hack', 'root', 'exploit', 'backdoor', 'webshell', 'uploader',
    'filemanager', 'cpanel', 'config_bak', 'test2', 'alfa',
    'indoxploit', 'symlink', 'spammer'
]

# =============================================
# Terminal Colors
# =============================================
class Colors:
    RED    = '\033[91m'
    YELLOW = '\033[93m'
    GREEN  = '\033[92m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

def cprint(text: str, color: str = Colors.RESET, bold: bool = False):
    prefix = Colors.BOLD if bold else ""
    print(f"{prefix}{color}{text}{Colors.RESET}")

# =============================================
# Helper Functions
# =============================================

def get_file_hash(filepath: str) -> str:
    """Compute MD5 hash of a file."""
    try:
        h = hashlib.md5()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"


def get_file_type(ext: str) -> str:
    """Determine which pattern set to use based on file extension."""
    ext = ext.lower()
    if ext in ['.php', '.php3', '.php4', '.php5', '.phtml']:
        return 'PHP'
    elif ext in ['.asp', '.aspx']:
        return 'ASP'
    elif ext in ['.jsp', '.jspx']:
        return 'JSP'
    return 'General'


def check_suspicious_name(filename: str) -> Tuple[bool, str]:
    """Check whether the filename matches known shell naming conventions."""
    name = os.path.splitext(filename)[0].lower()
    for sus in SUSPICIOUS_FILENAMES:
        if sus in name:
            return True, f"Suspicious filename contains keyword: '{sus}'"
    return False, ""


def check_suspicious_upload(filepath: str) -> Tuple[bool, str]:
    """Detect executable files placed inside upload directories."""
    path_lower = filepath.lower()
    upload_dirs = ['upload', 'files', 'media', 'images', 'static', 'assets']
    if any(folder in path_lower for folder in upload_dirs):
        ext = os.path.splitext(filepath)[1].lower()
        if ext in SUSPICIOUS_EXTENSIONS_IN_UPLOADS:
            return True, f"Executable file ({ext}) found inside an upload directory"
    return False, ""


def scan_file(filepath: str, file_type: str) -> List[Dict]:
    """Scan a file for malicious patterns and return a list of findings."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        patterns = SHELL_PATTERNS.get(file_type, []) + SHELL_PATTERNS.get('General', [])

        for pattern, description in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            if matches:
                line_num = 1
                for i, line in enumerate(content.splitlines(), 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        line_num = i
                        break
                findings.append({
                    "pattern": pattern[:50] + "..." if len(pattern) > 50 else pattern,
                    "description": description,
                    "line": line_num,
                    "matches": len(matches)
                })

    except (PermissionError, OSError):
        pass

    return findings


def calculate_risk(findings: List, name_suspicious: bool, upload_suspicious: bool) -> str:
    """Calculate an overall risk level for a file."""
    score = 0
    score += len(findings) * 2
    if name_suspicious:
        score += 3
    if upload_suspicious:
        score += 4

    if score >= 8:
        return "High Risk 🔴"
    elif score >= 4:
        return "Medium Risk 🟡"
    elif score >= 1:
        return "Suspicious 🟠"
    return "Clean ✅"


# =============================================
# Main Scanner
# =============================================

def scan_directory(
    path: str,
    extensions: List[str],
    max_size_mb: int = 5,
    report_path: str = None
) -> Dict:
    """Recursively scan a directory for web shells."""

    results = {
        "scan_info": {
            "path": path,
            "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "extensions": extensions,
        },
        "summary": {
            "total_scanned": 0,
            "total_suspicious": 0,
            "high_risk": 0
        },
        "findings": []
    }

    cprint(f"\n{'='*60}", Colors.CYAN, bold=True)
    cprint(f"  Web Shell Detector", Colors.CYAN, bold=True)
    cprint(f"{'='*60}", Colors.CYAN, bold=True)
    cprint(f"  Path      : {path}", Colors.BLUE)
    cprint(f"  Extensions: {', '.join(extensions)}", Colors.BLUE)
    cprint(f"  Date      : {results['scan_info']['date']}", Colors.BLUE)
    cprint(f"{'='*60}\n", Colors.CYAN, bold=True)

    scan_path = Path(path)
    if not scan_path.exists():
        cprint(f"❌ Path not found: {path}", Colors.RED, bold=True)
        sys.exit(1)

    all_files = []
    for ext in extensions:
        all_files.extend(scan_path.rglob(f"*{ext}"))

    total = len(all_files)
    cprint(f"📂 Found {total} files to scan...\n", Colors.BLUE)

    for i, filepath in enumerate(all_files, 1):
        filepath_str = str(filepath)
        filename = filepath.name
        ext = filepath.suffix
        file_type = get_file_type(ext)

        # Skip files that are too large
        try:
            size_mb = os.path.getsize(filepath_str) / (1024 * 1024)
            if size_mb > max_size_mb:
                continue
        except Exception:
            continue

        results["summary"]["total_scanned"] += 1

        name_sus, name_reason     = check_suspicious_name(filename)
        upload_sus, upload_reason = check_suspicious_upload(filepath_str)
        code_findings             = scan_file(filepath_str, file_type)

        is_suspicious = bool(code_findings or name_sus or upload_sus)

        if is_suspicious:
            results["summary"]["total_suspicious"] += 1
            risk = calculate_risk(code_findings, name_sus, upload_sus)

            color = Colors.RED if "High" in risk else Colors.YELLOW
            if "High" in risk:
                results["summary"]["high_risk"] += 1

            file_result = {
                "file": filepath_str,
                "size_kb": round(size_mb * 1024, 2),
                "md5": get_file_hash(filepath_str),
                "risk": risk,
                "reasons": []
            }

            cprint(f"\n{'─'*60}", color)
            cprint(f"⚠️  {filepath_str}", color, bold=True)
            cprint(f"   Risk  : {risk}", color)
            cprint(f"   Size  : {round(size_mb * 1024, 2)} KB  |  MD5: {file_result['md5']}", Colors.BLUE)

            if name_sus:
                cprint(f"   🔸 {name_reason}", Colors.YELLOW)
                file_result["reasons"].append(name_reason)

            if upload_sus:
                cprint(f"   🔸 {upload_reason}", Colors.YELLOW)
                file_result["reasons"].append(upload_reason)

            for finding in code_findings:
                reason = (
                    f"Line {finding['line']}: {finding['description']} "
                    f"({finding['matches']} match{'es' if finding['matches'] > 1 else ''})"
                )
                cprint(f"   🔴 {reason}", Colors.RED)
                file_result["reasons"].append(reason)

            results["findings"].append(file_result)

        # Progress bar
        if i % 50 == 0 or i == total:
            progress = int((i / total) * 40) if total > 0 else 40
            bar = '█' * progress + '░' * (40 - progress)
            print(f"\r   [{bar}] {i}/{total}", end='', flush=True)

    print()

    # =============================================
    # Summary
    # =============================================
    cprint(f"\n{'='*60}", Colors.CYAN, bold=True)
    cprint(f"  Scan Summary", Colors.CYAN, bold=True)
    cprint(f"{'='*60}", Colors.CYAN, bold=True)
    cprint(f"  Total files scanned  : {results['summary']['total_scanned']}", Colors.BLUE)
    cprint(f"  Suspicious files     : {results['summary']['total_suspicious']}", Colors.YELLOW)
    cprint(f"  High-risk files      : {results['summary']['high_risk']}", Colors.RED)

    if results['summary']['high_risk'] > 0:
        cprint(f"\n  ⚠️  Warning: Review high-risk files immediately!", Colors.RED, bold=True)
    elif results['summary']['total_suspicious'] > 0:
        cprint(f"\n  ⚠️  Review suspicious files as soon as possible.", Colors.YELLOW, bold=True)
    else:
        cprint(f"\n  ✅ No web shells detected.", Colors.GREEN, bold=True)

    cprint(f"{'='*60}\n", Colors.CYAN, bold=True)

    # Save report
    if report_path:
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            cprint(f"📄 Report saved to: {report_path}", Colors.GREEN)
        except Exception as e:
            cprint(f"❌ Failed to save report: {e}", Colors.RED)

    return results


# =============================================
# Entry Point
# =============================================

def main():
    parser = argparse.ArgumentParser(
        description="Web Shell Detector — scan your own server for malicious files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 shell_detector.py --path /var/www/html
  python3 shell_detector.py --path /home/user/public_html --report report.json
  python3 shell_detector.py --path /var/www --extensions php,asp,aspx
  python3 shell_detector.py --path /var/www --max-size 10
        """
    )

    parser.add_argument('--path', '-p', required=True,
                        help='Path to the directory to scan')
    parser.add_argument('--extensions', '-e', default='php,asp,aspx,jsp,phtml',
                        help='Comma-separated file extensions (default: php,asp,aspx,jsp,phtml)')
    parser.add_argument('--report', '-r', default=None,
                        help='Path to save the JSON report (optional)')
    parser.add_argument('--max-size', type=int, default=5,
                        help='Maximum file size in MB to scan (default: 5)')

    args = parser.parse_args()

    extensions = ['.' + e.strip().lstrip('.') for e in args.extensions.split(',')]

    scan_directory(
        path=args.path,
        extensions=extensions,
        max_size_mb=args.max_size,
        report_path=args.report
    )


if __name__ == "__main__":
    main()
