# TraceDNS

A powerful multi-source OSINT subdomain enumeration tool that collects, correlates, and deduplicates subdomains using both local reconnaissance tools and passive intelligence providers.

## Installation

Clone the repository and install the required dependencies.

```bash
git clone https://github.com/yourusername/TraceDNS.git && cd TraceDNS
```

```bash
pip install -r requirements.txt
```


## Usage

```sh
$ python reversint.py -d example.com

Options:
  -h, --help        Show this help message and exit
  -d, --domain      Target domain to enumerate
```

## Output

```bash
████████╗██████╗  █████╗  ██████╗███████╗██████╗ ███╗   ██╗███████╗
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝
   ██║   ██████╔╝███████║██║     █████╗  ██║  ██║██╔██╗ ██║███████╗
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██║  ██║██║╚██╗██║╚════██║
   ██║   ██║  ██║██║  ██║╚██████╗███████╗██████╔╝██║ ╚████║███████║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═════╝ ╚═╝  ╚═══╝╚══════╝

[+] Enumeration Summary

amass           - 120 subdomains
subfinder       - 98 subdomains
crt.sh          - 45 subdomains
securitytrails  - 32 subdomains
virustotal      - 18 subdomains
shodan          - 14 subdomains

[+] Total unique subdomains: 173
[+] Saved to example.com_subdomains.txt
```
## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

