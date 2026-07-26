# tls-organiser

A Python-based tool designed to make SSL/TLS vulnerability reporting more efficient.

Developed as a Proof of Concept to automate the consolidation of TLS-related Nessus findings into reporting-friendly root causes and generate reusable technical commentary, remediation guidance, and reference material.

The tool consumes platform vulnerability exports and transforms hundreds or thousands of SSL/TLS findings into a concise set of report-ready observations.

## Installation

### UV (Recommended):

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install tls-organiser via UV
uv tool install git+https://github.com/CSpanias/tls-organiser

# Verify installation
tls-organiser -h

# Update
uv tool upgrade tls-organiser
```

### Clone Locally

> **Note:** Python 3 must be installed and available in your PATH.

```bash
# Clone the repository
git clone https://github.com/CSpanias/tls-organiser /opt/tls-organiser

# Make the script executable
chmod +x /opt/tls-organiser/tls_organiser.py

# Create a symbolic link
sudo ln -s /opt/tls-organiser/tls_organiser.py /usr/local/bin/tls-organiser

# Verify installation
tls-organiser -h
```

## Features

The tool follows the same workflow typically used during SSL/TLS reviews and infrastructure vulnerability assessments.

### Vulnerability Consolidation
* Parse Platform XLS exports
* Identify SSL/TLS-related findings automatically
* Group individual plugins into reporting-friendly root causes
* Remove duplicate observations
* Count affected hosts, services, and vulnerability instances

### Report Generation
* Generate executive summary, technical commentary, and remediation guidance in Markdown format
* Deduplicate references automatically

## Usage

```bash
# Analyse an export
tls-organiser findings.xlsx
```

## Example Output

```bash
$ tls-organiser tls-vulns-merged.xlsx

[*] TLS Organiser v1.0

[+] Deprecated SSL Support                   Hosts: 29    Services: 44
[+] Deprecated TLS Support                   Hosts: 346   Services: 492
[+] Invalid TLS Certificate Configuration    Hosts: 440   Services: 736
[+] Weak Certificate Cryptography            Hosts: 78    Services: 86
[+] Weak Cipher Suites                       Hosts: 152   Services: 245
[+] Weak DH Parameters (Logjam)              Hosts: 24    Services: 35

[+] Findings Processed : 2968
[+] Root Causes        : 6
[+] Output File        : tls-review.md
```

## Supported Nessus Findings

| Root Cause                            | Plugin IDs                               |
| ------------------------------------- | ---------------------------------------- |
| Deprecated SSL Support                | 20007, 78447, 78479, 89058               |
| Deprecated TLS Support                | 104743, 157288                           |
| Weak Cipher Suites                    | 26928, 42873, 65821, 81606               |
| Invalid TLS Certificate Configuration | 15901, 45410, 45411, 51192, 57582, 56284 |
| Weak Certificate Cryptography         | 35291, 60108, 69551, 86067               |
| Weak DH Parameters (Logjam)           | 83875                                    |
| Anonymous Cipher Suites Supported     | 31705                                    |

## Requirements

* Python 3
* openpyxl

Roadmap
* ???