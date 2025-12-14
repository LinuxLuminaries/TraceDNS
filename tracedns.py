import os
import json
import argparse
import subprocess
import requests
import shutil
import sys
from colorama import Fore, Style, init

CONFIG_FILE = "osint_config.json"

init(autoreset=True)

BANNER = Fore.CYAN + r"""
████████╗██████╗  █████╗  ██████╗███████╗██████╗ ███╗   ██╗███████╗    
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝    
   ██║   ██████╔╝███████║██║     █████╗  ██║  ██║██╔██╗ ██║███████╗    
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██║  ██║██║╚██╗██║╚════██║    
   ██║   ██║  ██║██║  ██║╚██████╗███████╗██████╔╝██║ ╚████║███████║    
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═════╝ ╚═╝  ╚═══╝╚══════╝    
    Multi-source OSINT Subdomain Enumerator                                         
""" + Style.RESET_ALL

PROVIDERS = {
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "passivetotal": "PASSIVETOTAL_API_KEY"
}

LOCAL_TOOLS = ["amass", "subfinder"]


def first_run_setup():
    config = {}
    print("[+] First run detected. Please provide API keys (press Enter to skip)")
    for provider in PROVIDERS:
        key = input(f"{provider} API key: ").strip()
        if key:
            config[provider] = key
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
    print("[+] Configuration saved")
    return config


def load_config():
    if not os.path.exists(CONFIG_FILE):
        return first_run_setup()
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


def check_local_tools():
    missing = []
    for tool in LOCAL_TOOLS:
        if not shutil.which(tool):
            missing.append(tool)
    return missing


class Enumerator:
    def __init__(self, domain, config):
        self.domain = domain
        self.config = config
        self.results = {}

    def run_amass(self):
        try:
            output = subprocess.check_output(["amass", "enum", "-d", self.domain], text=True)
            self.results["amass"] = set(output.splitlines())
        except Exception:
            self.results["amass"] = set()

    def run_subfinder(self):
        try:
            output = subprocess.check_output(["subfinder", "-d", self.domain, "-silent"], text=True)
            self.results["subfinder"] = set(output.splitlines())
        except Exception:
            self.results["subfinder"] = set()

    def run_crtsh(self):
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            r = requests.get(url, timeout=15)
            subs = set()
            if r.status_code == 200:
                for entry in r.json():
                    for name in entry.get("name_value", "").split("\n"):
                        if name.endswith(self.domain):
                            subs.add(name.strip())
            self.results["crt.sh"] = subs
        except Exception:
            self.results["crt.sh"] = set()

    def run_securitytrails(self):
        if "securitytrails" not in self.config:
            return
        try:
            headers = {"APIKEY": self.config["securitytrails"]}
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            r = requests.get(url, headers=headers)
            self.results["securitytrails"] = {
                f"{s}.{self.domain}" for s in r.json().get("subdomains", [])
            }
        except Exception:
            self.results["securitytrails"] = set()

    def run_virustotal(self):
        if "virustotal" not in self.config:
            return
        try:
            headers = {"x-apikey": self.config["virustotal"]}
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
            r = requests.get(url, headers=headers)
            self.results["virustotal"] = {d["id"] for d in r.json().get("data", [])}
        except Exception:
            self.results["virustotal"] = set()

    def run_shodan(self):
        if "shodan" not in self.config:
            return
        try:
            url = f"https://api.shodan.io/dns/domain/{self.domain}?key={self.config['shodan']}"
            r = requests.get(url)
            self.results["shodan"] = {
                f["subdomain"] + "." + self.domain for f in r.json().get("subdomains", [])
            }
        except Exception:
            self.results["shodan"] = set()

    def run_passivetotal(self):
        if "passivetotal" not in self.config:
            return
        self.results["passivetotal"] = set()

    def run_all(self):
        if shutil.which("amass"):
            self.run_amass()
        if shutil.which("subfinder"):
            self.run_subfinder()
        self.run_crtsh()
        self.run_securitytrails()
        self.run_virustotal()
        self.run_shodan()
        self.run_passivetotal()

    def report(self):
        print("\n[+] Enumeration Summary\n")
        for source, subs in self.results.items():
            print(f"{source} - {len(subs)} subdomains")

        all_subs = set().union(*self.results.values()) if self.results else set()
        if not all_subs:
            print("[!] No subdomains found")
            return

        with open(f"{self.domain}_subdomains.txt", "w") as f:
            f.write("\n".join(sorted(all_subs)))

        print(f"\n[+] Total unique subdomains: {len(all_subs)}")
        print(f"[+] Saved to {self.domain}_subdomains.txt")


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Multi-source OSINT Subdomain Enumerator")
    parser.add_argument("-d", "--domain", required=True)
    args = parser.parse_args()
    

    missing_tools = check_local_tools()
    if missing_tools:
        print("[!] The following local tools are not installed:")
        for t in missing_tools:
            print(f"    - {t}")
        print("[!] These tools will be skipped.\n")

    config = load_config()
    if not config:
        print("[!] No API keys provided. API-based providers will be skipped.")

    if not config and not shutil.which("amass") and not shutil.which("subfinder"):
        print("[!] No APIs and no local tools available. Nothing to run. Exiting.")
        sys.exit(0)

    enum = Enumerator(args.domain, config)
    enum.run_all()
    enum.report()


if __name__ == "__main__":
    main()
