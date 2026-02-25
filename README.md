# TraceDNS

A multi-source OSINT subdomain enumeration tool that collects, correlates, and deduplicates subdomains using both local reconnaissance tools and passive intelligence providers.

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/yourusername/TraceDNS.git && cd TraceDNS
pip install -r requirements.txt
```

## Usage

```bash
python tracedns.py -d example.com
```

### CLI options

```text
-h, --help            Show this help message and exit
-d, --domain          Target domain to enumerate (required)
-t, --tool            Select one source or run all
                      Choices: all, amass, subfinder, crtsh, virustotal, securitytrails
-to, --timeout        Timeout per tool in seconds (default: 180)
-v, --verbose         Print live subdomain discoveries
--debug               Show provider/tool warnings and errors
```

## Output

TraceDNS prints a per-source summary and total unique subdomains, then writes deduplicated output to:

```text
output/<domain>_subdomains.txt
```

Example summary:

```text
========== FINAL REPORT ==========

Source              | Count
--------------------|-------
amass               | 120
subfinder           | 98
crtsh               | 45
securitytrails      | 32
virustotal          | 18
--------------------|-------
Total Unique        | 173
[*] Saved to output/example.com_subdomains.txt
```

## Configuration

Create an optional `osint_config.json` in the project root for API-based providers:

```json
{
  "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
  "securitytrails": "YOUR_SECURITYTRAILS_API_KEY"
}
```

If API keys are missing, those sources are skipped.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
