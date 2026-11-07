#!/usr/bin/env python3
"""
Parses .eml files from a watched folder and outputs JSON-lines
suitable for Wazuh ingestion. Designed to run on the Windows host
(via Task Scheduler) or Linux, watching a folder for new .eml files.
"""

import email
import json
import os
import re
import sys
from email import policy
from pathlib import Path
from datetime import datetime, timezone

WATCH_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./eml_inbox")
OUTPUT_LOG = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("./phishing_email.log")
PROCESSED_MARKER = Path("./.processed_emails")

URL_REGEX = re.compile(r'https?://[^\s"\'<>]+')
SUSPICIOUS_EXTENSIONS = {'.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.jar', '.wsf'}

def load_processed():
    if PROCESSED_MARKER.exists():
        return set(PROCESSED_MARKER.read_text().splitlines())
    return set()

def save_processed(processed):
    PROCESSED_MARKER.write_text("\n".join(processed))

def extract_domain(addr):
    match = re.search(r'@([\w.-]+)', addr or "")
    return match.group(1).lower() if match else ""

def get_body_text(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_content()
                except Exception:
                    return ""
    else:
        try:
            return msg.get_content()
        except Exception:
            return ""
    return ""

def parse_eml(filepath):
    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    from_addr = msg.get('From', '')
    reply_to = msg.get('Reply-To', '')
    subject = msg.get('Subject', '')
    to_addr = msg.get('To', '')

    from_domain = extract_domain(from_addr)
    reply_to_domain = extract_domain(reply_to) if reply_to else ""

    body = get_body_text(msg)
    urls = URL_REGEX.findall(body)

    attachments = []
    for part in msg.iter_attachments():
        fname = part.get_filename()
        if fname:
            attachments.append(fname)

    suspicious_attachments = [
        a for a in attachments
        if any(a.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
        or len(a.split('.')) > 2  # double extension check e.g. invoice.pdf.exe
    ]

    record = {
        "name": "phishing_email_scan",
        "hostIdentifier": os.environ.get("COMPUTERNAME", os.uname().nodename if hasattr(os, 'uname') else "unknown"),
        "calendarTime": datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y UTC"),
        "unixTime": int(datetime.now(timezone.utc).timestamp()),
        "columns": {
            "from": from_addr,
            "from_domain": from_domain,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "reply_to_mismatch": bool(reply_to_domain and reply_to_domain != from_domain),
            "to": to_addr,
            "subject": subject,
            "urls": urls,
            "url_count": len(urls),
            "attachments": attachments,
            "suspicious_attachments": suspicious_attachments,
            "has_suspicious_attachment": len(suspicious_attachments) > 0,
            "source_file": str(filepath.name)
        },
        "action": "added"
    }
    return record

def main():
    WATCH_DIR.mkdir(exist_ok=True)

    # If the output log is missing (deleted, rotated, reset for a fresh demo),
    # the processed-marker is no longer trustworthy -- nothing we "already
    # processed" actually made it into a log Wazuh can read. Drop the marker
    # so every .eml gets reprocessed and rewritten to the (new) log file.
    if not OUTPUT_LOG.exists() and PROCESSED_MARKER.exists():
        print(f"{OUTPUT_LOG} not found - resetting processed marker, will reprocess all emails")
        PROCESSED_MARKER.unlink()

    processed = load_processed()

    eml_files = sorted(WATCH_DIR.glob("*.eml"))
    new_records = []

    for f in eml_files:
        if f.name in processed:
            continue
        try:
            record = parse_eml(f)
            new_records.append(record)
            processed.add(f.name)
        except Exception as e:
            print(f"Error parsing {f}: {e}", file=sys.stderr)

    if new_records:
        with open(OUTPUT_LOG, 'a') as out:
            for r in new_records:
                out.write(json.dumps(r) + "\n")
        print(f"Processed {len(new_records)} new email(s)")
    else:
        print("No new emails to process")

    save_processed(processed)

if __name__ == "__main__":
    main()