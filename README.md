# CYB333Automated-Linux-Firewall-Health-Compliance-Checker
# CYB333 Final Project — User Account Audit Script

## Overview
This project is a Python-based security automation tool that audits user accounts and flags accounts that appear inactive based on a configurable inactivity threshold. The goal is to automate routine access-review hygiene checks and produce a clear report for follow-up actions.

## Objectives
- Read user account data from an input file (CSV or JSON)
- Parse and validate last login values
- Flag accounts that exceed an inactivity threshold (e.g., 30/60/90 days)
- Identify accounts that have never logged in (missing/blank last_login)
- Generate a report (console output + saved file)
- (Optional) Assign severity or recommended action

## Features
- Configurable inactivity threshold
- Input validation for missing/malformed dates
- Clear “flag reason” for each account
- Exportable report output

## Project Structure
- `src/` — main script(s)
- `data/` — sample input datasets (no real user data)
- `reports/` — generated output reports
- `screenshots/` — proof of successful runs (timestamp visible)

## Requirements / Dependencies
- Python 3.10+ (or your version)
- Standard libraries used: [csv, json, datetime, argparse, etc.]
- External libraries (if any): [list here or “None”】【]
## Test Cases
- **Windows (expected behavior):** If `ufw`/`iptables` are not detected, the script still generates a report explaining that Linux tools are unavailable on Windows.
- **Linux/WSL/VM (target behavior):** Detects `ufw` or `iptables`, collects rules, and flags potential issues based on rule output.
- **Report generation:** Confirms `reports/firewall_report.txt` is created on each run.
