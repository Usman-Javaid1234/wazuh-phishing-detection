# Browser Activity and Phishing Detection in Wazuh

SOC Team Task #4, ITSOLERA SOC Analyst Internship.
Author: Usman Javaid

This project extends Wazuh to detect phishing activity from two sources on a Windows endpoint:

1. **Browser activity.** Chrome history is collected with osquery and checked for suspicious URLs and domains.
2. **Phishing emails.** `.eml` files are parsed by a Python script into JSON logs, which Wazuh reads and checks against custom rules.

Both pipelines were built and validated live in the Wazuh dashboard.

## Environment

| Component | Details |
|---|---|
| Wazuh manager | 4.14.5 (OVA, Amazon Linux 2023), running as a VM on the host |
| Endpoint | Windows 11 host with the Wazuh agent and osquery |
| Browser | Google Chrome |
| Scripting | Python 3 |

## How it works

```
Chrome History (SQLite)
   -> osquery ATC table + scheduled query (chrome_history_query)
   -> osqueryd.results.log
   -> Wazuh agent osquery wodle
   -> Manager rules 100220-100225 -> Dashboard alerts

.eml files (eml_inbox)
   -> scripts/parse_eml.py
   -> phishing_email.log (JSON lines)
   -> Wazuh agent <localfile> (json)
   -> Manager rules 100230-100236 -> Dashboard alerts
```

## Repository structure

```
.
├── README.md
├── agent/
│   └── ossec-agent-snippet.xml      # osquery wodle and phishing_email.log localfile
├── manager/
│   └── ossec-manager-snippet.xml    # list entry and logall setting
├── osquery/
│   └── osquery.conf                 # Chrome history ATC and scheduled query
├── rules/
│   ├── local_rules.xml              # custom detection rules
│   └── local_decoder.xml            # custom decoder
├── lists/
│   └── phishing-domains             # CDB list of known phishing domains
├── scripts/
│   └── parse_eml.py                 # .eml to JSON-lines parser
├── samples/
│   ├── clean_01.eml
│   ├── phish_mismatch_01.eml
│   ├── phish_attachment_01.eml
│   └── phish_knowndomain_01.eml
├── docs/
│   ├── Task_4_Report.docx
│   └── wazuh_phishing_rebuild_guide.md
└── final_ossec.conf                 # full merged agent/manager reference config
```

## Detection rules

### Browser rules (group `chrome_history,phishing`)

| Rule ID | Level | Detects |
|---|---|---|
| 100220 | base | Chrome history result from osquery (`chrome_history_query`) |
| 100221 | 10 | Phishing keywords in the URL (login, verify, secure, and similar) |
| 100222 | 12 | High-risk TLDs (.tk, .click, .top, and similar) |
| 100223 | 14 | Domain found in the known phishing domain list |
| 100224 | 11 | Phishing hosted on free hosting platforms |
| 100225 | 13 | Brand impersonation in the URL |

MITRE ATT&CK: T1566.002 (Spearphishing Link).

### Email rules (group `phishing_email,phishing`)

| Rule ID | Level | Detects |
|---|---|---|
| 100230 | base | Parsed email record (`phishing_email_scan`) |
| 100231 | 10 | Reply-To domain differs from sender domain |
| 100232 | 9 | Urgency language in the subject |
| 100233 | 13 | Suspicious or double-extension attachment |
| 100234 | 11 | Sender from a high-risk TLD |
| 100235 | 14 | Known phishing domain in the email body |
| 100236 | 12 | Brand impersonation in the sender display name |

MITRE ATT&CK: T1566.001 (Spearphishing Attachment) and T1566.002 (Spearphishing Link).

## Setup

### 1. Manager

1. Copy `lists/phishing-domains` to `/var/ossec/etc/lists/phishing-domains`.
2. Add the `<list>` entry from `manager/ossec-manager-snippet.xml` inside `<ruleset>` in `/var/ossec/etc/ossec.conf`.
3. Copy `rules/local_rules.xml` to `/var/ossec/etc/rules/` and `rules/local_decoder.xml` to `/var/ossec/etc/decoders/`.
4. Keep `<logall>` and `<logall_json>` set to `no`. Leaving them on filled the manager disk during testing.
5. Restart the manager: `systemctl restart wazuh-manager`.

### 2. Windows endpoint

1. Install osquery and place `osquery/osquery.conf` in `C:\Program Files\osquery\`.
2. Create `osquery.flags` in the same folder with `--config_path=C:\Program Files\osquery\osquery.conf`.
3. Start the service: `net start osqueryd`.
4. Add the contents of `agent/ossec-agent-snippet.xml` to `C:\Program Files (x86)\ossec-agent\ossec.conf`.
5. Restart the agent: `net stop WazuhSvc` then `net start WazuhSvc`.

### 3. Email parser

Create the folders `C:\SOC\eml_inbox` and `C:\SOC\logs`, drop `.eml` files into `eml_inbox`, then run:

```
python C:\SOC\parse_eml.py C:\SOC\eml_inbox C:\SOC\logs\phishing_email.log
```

If the log file is deleted, the script resets its processed marker and reprocesses all emails.
The script can also be run on a schedule with Windows Task Scheduler.

## Testing

Use `samples/` to confirm the email pipeline.

| Sample | Expected result |
|---|---|
| `clean_01.eml` | No alert beyond the base record |
| `phish_mismatch_01.eml` | Reply-To mismatch, urgency subject, suspicious sender TLD |
| `phish_attachment_01.eml` | Suspicious attachment (`invoice_48213.pdf.exe`) |
| `phish_knowndomain_01.eml` | Known phishing domain in the body |

For the browser pipeline, visit a test URL in Chrome and check the dashboard (Threat Hunting or Discover) for rules in the `chrome_history` group. Rules can also be tested without waiting using `/var/ossec/bin/wazuh-logtest`.

Note: live osquery events are nested under `osquery.` (for example `osquery.columns.url`), while raw logtest JSON is not. Wrap test input in `{"osquery": {...}}` when testing browser rules.

## Challenges and lessons

- osquery runs as a Windows service only when `osquery.flags` points to the config file.
- The Wazuh CDB list does exact matching only, so regex rules were added for domain patterns in URLs.
- Duplicate osquery wodles or a missing `<disabled>no</disabled>` stop data from reaching the manager.
- The agent path on 64-bit Windows is `C:\Program Files (x86)\ossec-agent\`.
- `logall` on a small disk fills it quickly and puts OpenSearch into read-only mode.

More detail is in `docs/Task_4_Report.docx` and `docs/wazuh_phishing_rebuild_guide.md`.

## Data sources

The phishing domain list was built from public phishing feeds (OpenPhish). Review any feed license before redistributing the list.

## Acknowledgements

Thanks to Saif and ITSOLERA for the guidance and the opportunity.
