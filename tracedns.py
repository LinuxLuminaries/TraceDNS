import os
import json
import argparse
import subprocess
import requests
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

init(autoreset=True)

CONFIG_FILE = "osint_config.json"
LOCAL_TOOLS = ["amass", "subfinder"]

CYAN = Fore.CYAN
GREEN = Fore.GREEN
RED = Fore.RED
BLUE = Fore.BLUE
RESET = Style.RESET_ALL

ERROR = RED + "[!]" + RESET
INFO = BLUE + "[+]" + RESET
GOOD = GREEN + "[*]" + RESET
WARN = Fore.YELLOW + "[~]" + RESET

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
def check_local_tools(selected_tool):
    if selected_tool == "all":
        required_tools = LOCAL_TOOLS
    elif selected_tool in LOCAL_TOOLS:
        required_tools = [selected_tool]
    else:
        required_tools = []
    return [tool for tool in required_tools if not shutil.which(tool)]


# =========================
# ENUMERATOR
# =========================
class Enumerator:

    def __init__(self, domain, config, timeout, verbose=False, debug=False):
        self.domain = domain.strip().lower().rstrip(".")
        self.config = config
        self.timeout = timeout
        self.verbose = verbose
        self.debug = debug
        self.results = {}
        self.unique_subs = set()
        self.lock = threading.Lock()
        self.active_processes = []
        self.session = self._build_session()

    def _build_session(self):
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session = requests.Session()
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _debug_log(self, message):
        if self.debug:
            with print_lock:
                print(f"{WARN} {message}", flush=True)

    def _normalize_subdomain(self, sub):
        normalized = sub.strip().lower().rstrip(".")
        if normalized.startswith("*."):
            normalized = normalized[2:]

        try:
            normalized = normalized.encode("idna").decode("ascii")
        except UnicodeError as exc:
            self._debug_log(f"Normalization skipped for '{sub}': {exc}")
            return None

        if not normalized.endswith(self.domain):
            return None
        return normalized

    # ----------------------
    # SAFE ADD RESULT
    # ----------------------
    def _add_result(self, source, sub):
        normalized_sub = self._normalize_subdomain(sub)
        if not normalized_sub:
            return

        with self.lock:
            if normalized_sub not in self.unique_subs:
                self.unique_subs.add(normalized_sub)
                self.results.setdefault(source, set()).add(normalized_sub)

                if self.verbose:
                    with print_lock:
                        print(f"[{source}] {normalized_sub}", flush=True)

    # ----------------------
    # SUBPROCESS RUNNER
    # ----------------------
    def _run_subprocess_live(self, cmd, source):
        process = None
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )

            self.active_processes.append(process)
            stdout, _ = process.communicate(timeout=self.timeout)
            for line in stdout.splitlines():
                sub = line.strip()
                if sub:
                    self._add_result(source, sub)

        except subprocess.TimeoutExpired:
            if process:
                process.kill()
                process.communicate()
            self._debug_log(
                f"Source '{source}' timed out after {self.timeout}s: {' '.join(cmd)}"
            )
        except Exception as exc:
            self._debug_log(f"Source '{source}' failed: {exc}")

    # =====================
    # LOCAL TOOLS
    # =====================
    def run_amass(self):
        self._run_subprocess_live(
            ["amass", "enum", "-d", self.domain],
            "amass"
        )

    def run_subfinder(self):
        self._run_subprocess_live(
            ["subfinder", "-d", self.domain, "-silent"],
            "subfinder"
        )

    # =====================
    # API PROVIDERS
    # =====================
    def run_crtsh(self):
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            r = self.session.get(url, timeout=20)
            if r.status_code == 200:
                for entry in r.json():
                    names = entry.get("name_value", "").split("\n")
                    for n in names:
                        self._add_result("crtsh", n)
            else:
                self._debug_log(f"crt.sh returned status {r.status_code}")
        except Exception as exc:
            self._debug_log(f"crt.sh request failed: {exc}")

    def run_virustotal(self):
        api_key = self.config.get("virustotal")
        if not api_key:
            return
        try:
            headers = {"x-apikey": api_key}
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
            r = self.session.get(url, headers=headers, timeout=25)
            if r.status_code == 200:
                for item in r.json().get("data", []):
                    self._add_result("virustotal", item["id"])
            else:
                self._debug_log(f"VirusTotal returned status {r.status_code}")
        except Exception as exc:
            self._debug_log(f"VirusTotal request failed: {exc}")

    def run_securitytrails(self):
        api_key = self.config.get("securitytrails")
        if not api_key:
            return
        try:
            headers = {"apikey": api_key}
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            r = self.session.get(url, headers=headers, timeout=25)
            if r.status_code == 200:
                for sub in r.json().get("subdomains", []):
                    self._add_result("securitytrails", f"{sub}.{self.domain}")
            else:
                self._debug_log(f"SecurityTrails returned status {r.status_code}")
        except Exception as exc:
            self._debug_log(f"SecurityTrails request failed: {exc}")

    # =====================
    # EXECUTION
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
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    self._debug_log(f"Worker failed: {exc}")

    # =====================
    # CLEANUP
    # =====================
    def kill_processes(self):
        for p in self.active_processes:
            try:
                p.kill()
            except ProcessLookupError:
                continue
            except Exception as exc:
                self._debug_log(f"Failed to kill process: {exc}")

    # =====================
    # REPORT
    # =====================
    def report(self):
        print("\n\n========== FINAL REPORT ==========\n")
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
    parser.add_argument("-t", "--tool", default="all",
                        choices=["all", "amass", "subfinder",
                                 "crtsh", "virustotal", "securitytrails"])
    parser.add_argument("-to", "--timeout", type=int,
                        default=180,
                        help="Timeout per tool in seconds")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable live domain output")
    parser.add_argument("--debug", action="store_true",
                        help="Show provider/tool errors and warnings")

    args = parser.parse_args()

    config = load_config()

    missing = check_local_tools(args.tool)
    if missing:
        print(f"{ERROR} Missing tools: {', '.join(missing)}")

    api_keys_loaded = [key for key, value in config.items() if value]
    print(f"{INFO} Tools running: {args.tool}")
    print(f"{INFO} API keys loaded: {len(api_keys_loaded)}")

    if api_keys_loaded:
        print(f"{INFO} Loaded key names: {', '.join(api_keys_loaded)}")
    else:
        print(f"{INFO} No API keys loaded.")

    enum = Enumerator(
        args.domain,
        config,
        args.timeout,
        verbose=args.verbose,
        debug=args.debug,
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
