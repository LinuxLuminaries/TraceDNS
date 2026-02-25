import os
import json
import argparse
import subprocess
import requests
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

CONFIG_FILE = "osint_config.json"
LOCAL_TOOLS = ["amass", "subfinder"]

CYAN = Fore.CYAN
GREEN = Fore.GREEN
RED = Fore.RED
BLUE = Fore.BLUE
RESET = Style.RESET_ALL

INFO = BLUE + "[+]" + RESET
GOOD = GREEN + "[*]" + RESET
ERROR = RED + "[!]" + RESET

print_lock = threading.Lock()


# =========================
# CONFIG SYSTEM
# =========================
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


# =========================
# TOOL CHECK
# =========================
def check_local_tools():
    return [tool for tool in LOCAL_TOOLS if not shutil.which(tool)]


# =========================
# ENUMERATOR
# =========================
class Enumerator:

    def __init__(self, domain, config, timeout=180, verbose=False):
        self.domain = domain
        self.config = config
        self.timeout = timeout or 180
        self.verbose = verbose
        self.results = {}
        self.unique_subs = set()
        self.lock = threading.Lock()
        self.active_processes = []

    # ----------------------
    # ADD RESULT
    # ----------------------
    def _add_result(self, source, sub):
        with self.lock:
            if sub not in self.unique_subs:
                self.unique_subs.add(sub)
                self.results.setdefault(source, set()).add(sub)

                if self.verbose:
                    with print_lock:
                        print(f"[{source}]{sub}", flush=True)

    # ----------------------
    # SAFE SUBPROCESS EXECUTION
    # ----------------------
    def _run_subprocess(self, cmd, source):

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        self.active_processes.append(process)

        try:
            stdout, _ = process.communicate(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            print(f"{ERROR} {source} timed out after {self.timeout} seconds")
            return

        if stdout:
            for line in stdout.splitlines():
                sub = line.strip()
                if sub.endswith(self.domain):
                    self._add_result(source, sub)

        count = len(self.results.get(source, []))
        print(f"\n{GOOD} [{source}] completed → {count} domains")

    # =====================
    # LOCAL TOOLS
    # =====================
    def run_amass(self):
        self._run_subprocess(
            ["amass", "enum", "-d", self.domain],
            "amass"
        )

    def run_subfinder(self):
        self._run_subprocess(
            ["subfinder", "-d", self.domain, "-silent"],
            "subfinder"
        )

    # =====================
    # API PROVIDERS
    # =====================
    def run_crtsh(self):
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            r = requests.get(url, timeout=20)
            if r.status_code == 200:
                for entry in r.json():
                    names = entry.get("name_value", "").split("\n")
                    for n in names:
                        n = n.strip()
                        if n.endswith(self.domain):
                            self._add_result("crtsh", n)
        except:
            pass

        count = len(self.results.get("crtsh", []))
        print(f"{GOOD} crtsh completed → {count} domains")

    def run_virustotal(self):
        api_key = self.config.get("virustotal")
        if not api_key:
            return

        try:
            headers = {"x-apikey": api_key}
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
            r = requests.get(url, headers=headers, timeout=25)
            if r.status_code == 200:
                for item in r.json().get("data", []):
                    self._add_result("virustotal", item["id"])
        except:
            pass

        count = len(self.results.get("virustotal", []))
        print(f"{GOOD} virustotal completed → {count} domains")

    def run_securitytrails(self):
        api_key = self.config.get("securitytrails")
        if not api_key:
            return

        try:
            headers = {"apikey": api_key}
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            r = requests.get(url, headers=headers, timeout=25)
            if r.status_code == 200:
                for sub in r.json().get("subdomains", []):
                    self._add_result("securitytrails", f"{sub}.{self.domain}")
        except:
            pass

        count = len(self.results.get("securitytrails", []))
        print(f"{GOOD} securitytrails completed → {count} domains")

    # =====================
    # EXECUTION CONTROLLER
    # =====================
    def run_selected(self, selected_tool):

        tool_map = {
            "amass": self.run_amass,
            "subfinder": self.run_subfinder,
            "crtsh": self.run_crtsh,
            "virustotal": self.run_virustotal,
            "securitytrails": self.run_securitytrails,
        }

        if selected_tool == "all":
            funcs = tool_map.values()
        else:
            funcs = [tool_map.get(selected_tool)]

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(f) for f in funcs if f]

            try:
                for future in as_completed(futures):
                    future.result()
            except KeyboardInterrupt:
                print(f"\n{ERROR} Interrupted by user. Exiting...")
                self.kill_processes()
                raise

    # =====================
    # KILL PROCESSES
    # =====================
    def kill_processes(self):
        for p in self.active_processes:
            try:
                p.kill()
            except:
                pass

    # =====================
    # FINAL REPORT
    # =====================
    def report(self):
        print("\n========== FINAL REPORT ==========\n")
        print("Source              | Count")
        print("--------------------|-------")

        for src, subs in self.results.items():
            print(f"{src:<20}| {len(subs)}")

        print("--------------------|-------")
        print(f"Total Unique        | {len(self.unique_subs)}")

        if not self.unique_subs:
            return

        os.makedirs("output", exist_ok=True)
        outfile = f"output/{self.domain}_subdomains.txt"

        with open(outfile, "w") as f:
            f.write("\n".join(sorted(self.unique_subs)))

        print(f"\n{GOOD} Saved to {outfile}")


# =========================
# MAIN
# =========================
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument(
        "-t",
        "--tool",
        default="all",
        choices=["all", "amass", "subfinder",
                 "crtsh", "virustotal", "securitytrails"]
    )
    parser.add_argument(
        "-to",
        "--timeout",
        type=int,
        default=180,
        help="Timeout per subprocess tool (default 180 sec)"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose live domain output"
    )

    args = parser.parse_args()

    config = load_config()

    missing = check_local_tools()
    if missing:
        print(f"{ERROR} Missing tools: {', '.join(missing)}")

    api_keys_loaded = sum(1 for v in config.values() if v)
    print(f"{INFO} API keys loaded: {api_keys_loaded} out of 4")

    enum = Enumerator(
        args.domain,
        config,
        timeout=args.timeout,
        verbose=args.verbose
    )

    try:
        enum.run_selected(args.tool)
    except KeyboardInterrupt:
        print(f"\n{ERROR} Interrupted by user. Exiting...")
        enum.kill_processes()
        enum.report()
        return

    enum.report()


if __name__ == "__main__":
    main()
