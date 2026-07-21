# 🛡️ VirusTotal Check Tool

Scan IP addresses, file hashes, domains, and URLs against the **VirusTotal API** with style. 🚀

## ✨ Features

- **🧠 Multi-type IOC scanning** — Auto-detects IP, file hash (MD5/SHA-1/SHA-256), domain, and URL — no need to specify the type manually.
- **📦 Batch file mode** — Scan up to **500 indicators** from a file (one per line).  
  ⚠️ *Requires VirusTotal Premium API key for high-volume scanning.*
- **⚡ Configurable threading** — Choose your speed: 1, 3 (default), 5, or 8 concurrent workers.
- **📁 Multi-format output** — Save results as `txt`, `csv`, `json`, `html`, or `pdf`.  
  Use `--format all` to generate **all formats at once** in a single run.
- **📊 Rich result enrichment** — See malicious/suspicious/harmless/undetected counts, popular threat labels, threat categories, family labels, and IP details at a glance.
- **🔒 IOC defanging** — IPs, domains, and URLs are automatically defanged in all output (e.g., `8.8.8[.]8`, `example[.]com`, `hxxps[://]`).
- **🛑 Smart quota handling** — Detects 429 / QuotaExceeded errors, stops further checks immediately, and saves partial results so you don't lose progress.
- **📄 Beautiful PDF reports** — Clean, professional multi-page PDF with summary cards, color-coded result rows, and repeated headers.

## 📋 Requirements

- Python 3.9+
- `fpdf2` (for PDF output)

Install dependencies:

```bash
pip3 install -r requirements.txt
```

## 🎯 How to Use

### Single IOC scan

```bash
# IP address
python3 virustotal_check.py --ip 8.8.8.8

# File hash (MD5, SHA-1, SHA-256)
python3 virustotal_check.py --hash d41d8cd98f00b204e9800998ecf8427e

# Domain
python3 virustotal_check.py --domain example.com

# URL
python3 virustotal_check.py --url https://example.com
```

### Batch file scan

Create a text file with one indicator per line:

```
8.8.8.8
d41d8cd98f00b204e9800998ecf8427e
example.com
https://example.com
```

```bash
# Default 3 threads
python3 virustotal_check.py --file indicators.txt

# With 8 threads and all output formats
python3 virustotal_check.py --file indicators.txt --thread 8 --format all --output report
```

### Output formats

```bash
# Single format
python3 virustotal_check.py --domain google.com --format pdf --output result.pdf

# All formats at once
python3 virustotal_check.py --domain google.com --format all --output result
```

This generates: `result.txt`, `result.csv`, `result.json`, `result.html`, `result.pdf`

### Thread speed options

| Threads | Use case |
|---|---|
| `1` | Minimal API usage, slow but safe |
| `3` | Default — balanced speed |
| `5` | Fast scanning |
| `8` | Maximum throughput |

```bash
python3 virustotal_check.py --file indicators.txt --thread 8
```

### Auto-stop on quota exceeded

When the VirusTotal API returns a 429 / QuotaExceeded error, the tool automatically stops all remaining checks and saves the results collected so far.
