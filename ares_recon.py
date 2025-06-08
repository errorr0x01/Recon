#!/usr/bin/env python3
"""
Project Ares - The Perfected Offensive Reconnaissance Engine v9.6

A self-learning, zero-cost, and fully integrated engine designed for elite
bug bounty hunting. Ares autonomously discovers, analyzes, and pivots on
vulnerabilities to conquer the entire attack surface.

*** WARNING: This is an active offensive tool. Use responsibly and only with explicit permission. ***
"""
import argparse
import subprocess
import os
import sys
import shutil
import json
import re
import random
from pathlib import Path
from datetime import datetime
import time
import base64
import requests
import mmh3
try:
    from graphviz import Digraph
except ImportError:
    print("Graphviz library not found. Please run 'pip install graphviz'. Visualization will be disabled.")
    Digraph = None

# --- Configuration ---
class C:
    HEADER = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'; GREEN = '\033[92m'
    YELLOW = '\033[93m'; RED = '\033[91m'; END = '\033[0m'; BOLD = '\033[1m'

CONFIG = {
    ### ============================================================================== ###
    ### !!! IMPORTANT !!! PASTE YOUR DISCORD WEBHOOK URL HERE                          ###
    "DISCORD_WEBHOOK_URL": "YOUR_DISCORD_WEBHOOK_URL_GOES_HERE",
    ### ============================================================================== ###
    
    "USER_AGENTS": [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    ]
}

# --- Core Helper Functions ---

def print_banner():
    banner = f"""{C.BOLD}{C.RED}
    ▄▀█─█▀█─█▀▀─█▀▀   █▀█─█▀▀─█▀▀─█▀▄─█▀
    █▀█─█▀▄─█───█▀──   █▄█─█▀▀─█▀──█▀▄─▄█
    {C.END}{C.YELLOW}          Project Ares: The Perfected Offensive Reconnaissance Engine v9.6{C.END}"""
    print(banner)

def check_dependencies():
    print(f"{C.HEADER}[*] Checking Ares Arsenal...{C.END}")
    tools = ["subfinder", "naabu", "httpx", "katana", "nuclei", "dnsx", "gau", "gows", "ffuf", "paramspider", "unfurl"]
    missing = [tool for tool in tools if not shutil.which(tool)]
    if missing:
        print(f"{C.RED}[!] The following components are missing from the Arsenal: {', '.join(missing)}{C.END}")
        sys.exit(1)
    if not Digraph:
        print(f"{C.YELLOW}[!] The 'graphviz' Python library is missing. Visualization will be disabled. Run 'pip install graphviz'.{C.END}")
    print(f"{C.GREEN}[✔] Ares Arsenal is fully stocked and operational.{C.END}\n")

def run_command(command, log_file, timeout=None):
    try:
        process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        with open(log_file, "a") as f:
            f.write(f"\n--- Ran: {command} ---\nSTDOUT:\n{process.stdout}\nSTDERR:\n{process.stderr}\n")
        return process.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"{C.YELLOW}[~] Command '{command.split()[0]}' timed out and was terminated.{C.END}")
        return ""
    except Exception as e:
        print(f"{C.RED}[!] Error running command '{command}': {e}{C.END}")
        return ""

def send_discord_alert(title, details, severity, is_propagated=False):
    webhook_url = CONFIG["DISCORD_WEBHOOK_URL"]
    if not webhook_url or "YOUR_DISCORD" in webhook_url: return

    color_map = {"CRITICAL": 15158332, "HIGH": 15105570, "MEDIUM": 16776960, "LOW": 3066993, "INFO": 3447003}
    color = color_map.get(severity.upper(), 3447003)
    icon = "https://i.imgur.com/2Qu32v2.png" # Ares icon

    if is_propagated:
        title = f"[PROPAGATED THREAT] {title}"
        details["Justification"] = "Ares hypothesized this vulnerability based on an initial finding on another asset."

    fields = [{"name": key, "value": f"```{value}```", "inline":False} for key, value in details.items()]
    embed = {
        "title": f"🔥 {title}" if severity.upper() == "CRITICAL" else f"🚨 {title}",
        "description": f"**Severity:** `{severity.upper()}`",
        "color": color, "fields": fields,
        "footer": {"text": f"Ares Engine | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "icon_url": icon}
    }
    payload = {"username": "Ares Offensive Bot", "embeds": [embed]}
    try: requests.post(webhook_url, json=payload, timeout=10)
    except Exception: pass

# --- Ares "AI" Core & Discovery Modules ---

class ThreatDB:
    def __init__(self, db_path):
        self.db_path = db_path
        self.db = self._load()

    def _load(self):
        if self.db_path.exists():
            with open(self.db_path, 'r') as f:
                try: return json.load(f)
                except json.JSONDecodeError: return {}
        return {}

    def _save(self):
        with open(self.db_path, 'w') as f: json.dump(self.db, f, indent=2)

    def learn(self, finding):
        tech_tags = [tag for tag in finding.get("info", {}).get("tags", "").split(',') if tag and tag not in ['cve', 'disclosure', 'osint']]
        template_path = finding.get("template-path")
        if not tech_tags or not template_path: return

        for tech in tech_tags:
            if tech not in self.db: self.db[tech] = []
            if template_path not in self.db[tech]:
                self.db[tech].append(template_path)
                print(f"{C.CYAN}[Ares LEARN]: Associated tech '{tech}' with threat pattern '{Path(template_path).name}'{C.END}")
        self._save()

    def generate_hypotheses(self, tech_info_file):
        hypotheses = []
        if not tech_info_file.exists(): return []
        tech_map = {}
        with open(tech_info_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    tech_map[data['url']] = [tech.lower() for tech in data.get('tech', [])]
                except (json.JSONDecodeError, KeyError): continue

        for tech_pattern, exploit_templates in self.db.items():
            for host, host_techs in tech_map.items():
                if tech_pattern in host_techs:
                    for template in exploit_templates:
                        hypotheses.append({"target": host, "exploit": template})
        
        return [dict(t) for t in {tuple(d.items()) for d in hypotheses}]

class AttackGraph:
    def __init__(self, output_path):
        self.dot = Digraph('Ares_Kill_Chain', comment='Automated Attack Path') if Digraph else None
        if self.dot: self.dot.attr(rankdir='LR', size='12,10', bgcolor='transparent', node={'shape': 'box', 'style': 'filled', 'fontname': 'Helvetica'})
        self.output_path = output_path
        self.nodes = set()

    def add_node(self, node_id, label, shape='box', color='lightblue'):
        if not self.dot or node_id in self.nodes: return
        self.dot.node(str(node_id), str(label), color=color, shape=shape)
        self.nodes.add(node_id)

    def add_edge(self, source, dest, label, color='black'):
        if not self.dot: return
        source_id = re.sub(r'[^a-zA-Z0-9_-]', '_', source)
        dest_id = re.sub(r'[^a-zA-Z0-9_-]', '_', dest)
        self.add_node(source_id, source)
        self.add_node(dest_id, dest, color='lightcoral' if "VULN" in dest else 'lightblue')
        self.dot.edge(source_id, dest_id, label=str(label), color=color, fontname="Helvetica", fontsize="10")
        
    def render(self):
        if not self.dot: return
        try:
            self.dot.render(self.output_path, format='png', view=False, cleanup=True)
            print(f"{C.GREEN}[✔] Attack path graph generated: {self.output_path}.png{C.END}")
        except Exception as e:
            print(f"{C.RED}[!] Failed to render attack graph. Is Graphviz installed system-wide? Error: {e}{C.END}")

def get_shodan_ips_pythonic(query):
    print(f"{C.CYAN}[>] Querying Shodan's free search with: '{query}'{C.END}")
    try:
        encoded_query = requests.utils.quote(query)
        url = f"https://www.shodan.io/search/facet?query={encoded_query}&facet=ip"
        headers = {'User-Agent': random.choice(CONFIG['USER_AGENTS'])}
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        private_ip_pattern = re.compile(r"^(127\.)|(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)|(192\.168\.)")
        return list({ip for ip in ip_pattern.findall(response.text) if not private_ip_pattern.match(ip)})
    except requests.RequestException:
        return []

def get_favicon_hash_and_search(domain_url):
    print(f"{C.CYAN}[>] Searching for assets via Favicon correlation...{C.END}")
    try:
        response = requests.get(f"{domain_url}/favicon.ico", verify=False, timeout=10, headers={'User-Agent': random.choice(CONFIG['USER_AGENTS'])})
        if response.status_code == 200 and response.content:
            favicon = base64.encodebytes(response.content)
            favi_hash = mmh3.hash(favicon)
            print(f"{C.GREEN}[✔] Found Favicon hash: {favi_hash}{C.END}")
            return get_shodan_ips_pythonic(f'http.favicon.hash:{favi_hash}')
        return []
    except Exception:
        return []

def infrastructure_predictor(subdomains_file):
    if not subdomains_file.exists(): return set()
    print(f"{C.CYAN}[Ares PREDICT]: Analyzing infrastructure naming patterns...{C.END}")
    siblings, env_patterns = set(), ['dev', 'stage', 'staging', 'qa', 'test', 'uat', 'prod', 'demo', 'api', 'admin', 'internal']
    with open(subdomains_file, 'r') as f: subdomains = {line.strip() for line in f}
    for sub in subdomains:
        for pat in env_patterns:
            if sub.startswith(pat + '-') or sub.startswith(pat + '.'):
                base = re.split(f'^{pat}[-.]', sub, 1)[1]
                for p in env_patterns:
                    siblings.add(f"{p}-{base}"); siblings.add(f"{p}.{base}")
    new_targets = siblings - subdomains
    if new_targets: print(f"{C.GREEN}[✔] Predicted {len(new_targets)} new sibling infrastructure targets.{C.END}")
    return new_targets

# --- Main Orchestration ---
def main():
    parser = argparse.ArgumentParser(description="Ares - The Perfected Offensive Reconnaissance Engine v9.6.", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-d", "--domain", required=True, help="The target root domain to attack.")
    parser.add_argument("--dry-run", action="store_true", help="Run all reconnaissance and analysis phases without executing offensive Nuclei scans.")
    parser.add_argument("--i-have-permission", action="store_true", help="Acknowledge you have explicit, legal authorization for this offensive scan.")
    args = parser.parse_args()

    if not args.i_have_permission:
        print(f"{C.RED}{C.BOLD}[!] ERROR: This is a powerful offensive tool. You must have explicit, written, legal authorization.{C.END}")
        print(f"{C.RED}{C.BOLD}[!] Rerun with the '--i-have-permission' flag to acknowledge this responsibility.{C.END}")
        sys.exit(1)

    print_banner(); check_dependencies()

    target_domain = args.domain
    output_dir = Path(f"ares_{target_domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    output_dir.mkdir()
    
    recon_dir, vuln_dir, content_dir = output_dir / "recon", output_dir / "vulns", output_dir / "content"
    recon_dir.mkdir(); vuln_dir.mkdir(); content_dir.mkdir()

    log_file = output_dir / "ares_activity.log"
    attack_graph = AttackGraph(output_dir / "attack_path")
    attack_graph.add_node(target_domain, f"ROOT TARGET\n{target_domain}", shape='star', color='red')
    
    print(f"{C.HEADER}--- Activating Ares Engine on: {target_domain} ---{C.END}")
    send_discord_alert(f"Ares Scan Engaged: {target_domain}", {"Target": target_domain, "Mode": "Dry Run" if args.dry_run else "Offensive"}, "INFO")

    subdomains_file, historical_urls_file = recon_dir / "subdomains.txt", recon_dir / "urls_historical.txt"
    all_ips_file, ports_file = recon_dir / "ips_all.txt", recon_dir / "ports_open.txt"
    live_hosts_file, tech_info_file = recon_dir / "hosts_live.txt", recon_dir / "hosts_tech.jsonl"
    all_urls_file, dynamic_wordlist = content_dir / "urls_all.txt", content_dir / "wordlist_dynamic.txt"
    ffuf_results, param_file = content_dir / "ffuf.json", content_dir / "params.txt"
    initial_vulns_file, propagated_vulns_file = vuln_dir/"nuclei_initial.jsonl", vuln_dir/"nuclei_propagated.jsonl"
    db = ThreatDB(output_dir / "threat_db.json")

    # Phase 1: Multi-Vector Asset Discovery
    print(f"\n{C.BLUE}--- Phase 1: Multi-Vector Asset Discovery ---{C.END}")
    run_command(f"subfinder -d {target_domain} -o {subdomains_file} -silent", log_file)
    predicted_siblings = infrastructure_predictor(subdomains_file)
    if predicted_siblings:
        with open(subdomains_file, 'a') as f: f.write("\n" + "\n".join(predicted_siblings))
        attack_graph.add_edge(target_domain, "Predicted Siblings", f"Predicted {len(predicted_siblings)}\nSiblings")

    run_command(f"gau --subs --threads 20 --o {historical_urls_file} {target_domain}", log_file, timeout=600)
    run_command(f"httpx -l {subdomains_file} -o {live_hosts_file} -json -oJ {tech_info_file} -silent -threads 50 -tech-detect", log_file)
    
    shodan_domain_ips = get_shodan_ips_pythonic(f'ssl:"{target_domain}"')
    main_url = next((line.strip() for line in open(live_hosts_file) if f"https://{target_domain}" in line), f"https://{target_domain}") if live_hosts_file.exists() else f"https://{target_domain}"
    shodan_favi_ips = get_favicon_hash_and_search(main_url)
    all_ips = set(shodan_domain_ips + shodan_favi_ips)
    if subdomains_file.exists(): all_ips.update(run_command(f"dnsx -l {subdomains_file} -a -resp-only -silent", log_file).splitlines())
    if all_ips:
        with open(all_ips_file, "w") as f: f.write("\n".join(sorted(list(all_ips))))
        run_command(f"naabu -l {all_ips_file} -top-ports 1000 -o {ports_file} -silent -rate 1500", log_file)
        attack_graph.add_edge(target_domain, "Discovered IPs", f"Found {len(all_ips)} IPs")

    # Phase 2: Deep Content Analysis
    print(f"\n{C.BLUE}--- Phase 2: Deep Content & Attack Surface Analysis ---{C.END}")
    run_command(f"gows -i {live_hosts_file} -o {content_dir / 'visual'} --threads 10", log_file)
    with open(all_urls_file, 'w') as f:
        if live_hosts_file.exists(): f.write(open(live_hosts_file).read() + "\n")
        if historical_urls_file.exists(): f.write(open(historical_urls_file).read() + "\n")
    run_command(f"cat {all_urls_file} | unfurl -u keys | sort -u > {dynamic_wordlist}", log_file)
    run_command(f"ffuf -w {dynamic_wordlist} -L {live_hosts_file} -o {ffuf_results} -of json -c -maxtime-job 300 -rate 50", log_file, timeout=1800)
    run_command(f"paramspider -l {live_hosts_file} --level high -o {param_file}", log_file)
    
    if args.dry_run:
        print(f"\n{C.YELLOW}[DRY RUN]: Offensive phases skipped. Reconnaissance and analysis complete.{C.END}")
        attack_graph.render()
        sys.exit(0)

    # Phase 3: Initial Offensive Strike
    print(f"\n{C.BLUE}--- Phase 3: Initial Offensive Strike ---{C.END}")
    send_discord_alert(f"Ares Scan Update: {target_domain}", {"Status": "Phase 3: Initial Offensive Scan"}, "INFO")
    run_command(f"nuclei -l {live_hosts_file} -t cves/,vulnerabilities/,misconfigurations/,exposures/ -es info,low -o {initial_vulns_file} -jsonl -silent -rate 150", log_file)
    
    # Phase 4: Ares Thinks - Learning from the Hunt
    print(f"\n{C.CYAN}--- Phase 4: Ares is Thinking... Analyzing Battlefield Data... ---{C.END}")
    if initial_vulns_file.exists():
        with open(initial_vulns_file, 'r') as f:
            for line in f:
                try:
                    finding = json.loads(line)
                    db.learn(finding)
                    details = {"Template": Path(finding.get("template-path")).name, "Host": finding.get("host"), "Details": finding.get("info", {}).get("description", "N/A")}
                    send_discord_alert(f"Initial Finding: {finding['info']['name']}", details, finding['info']['severity'])
                    attack_graph.add_edge(finding['host'], f"VULN: {finding['info']['name']}", label=f"{finding['info']['severity']}", color='red')
                except (json.JSONDecodeError, KeyError): continue

    # Phase 5: Ares Acts - Threat Propagation
    print(f"\n{C.CYAN}--- Phase 5: Ares is Pivoting... Propagating Threats... ---{C.END}")
    hypotheses = db.generate_hypotheses(tech_info_file)
    if hypotheses:
        send_discord_alert(f"Ares Scan Update: {target_domain}", {"Status": f"Phase 5: Propagating {len(hypotheses)} Threats"}, "INFO")
        time.sleep(3)
        grouped_by_exploit = {}
        for h in hypotheses:
            exploit = h['exploit']
            if exploit not in grouped_by_exploit: grouped_by_exploit[exploit] = set()
            grouped_by_exploit[exploit].add(h['target'])
        
        for exploit, targets in grouped_by_exploit.items():
            temp_target_file = recon_dir / "temp_ares_targets.txt"
            with open(temp_target_file, 'w') as f: f.write("\n".join(targets))
            run_command(f"nuclei -l {temp_target_file} -t {exploit} -o {propagated_vulns_file} -jsonl -silent -rate 50 -append", log_file)
            temp_target_file.unlink()
    
    if propagated_vulns_file.exists():
        with open(propagated_vulns_file, 'r') as f:
            for line in f:
                try:
                    finding = json.loads(line)
                    details = {"Template": Path(finding.get("template-path")).name, "Host": finding.get("host")}
                    send_discord_alert(f"Confirmed Finding: {finding['info']['name']}", details, finding['info']['severity'], is_propagated=True)
                    attack_graph.add_edge(finding['host'], f"VULN: {finding['info']['name']}", label=f"{finding['info']['severity']}\n(Propagated)", color='orange')
                except (json.JSONDecodeError, KeyError): continue

    attack_graph.render()
    print(f"\n{C.BOLD}{C.GREEN}--- ARES ENGINE HAS COMPLETED ITS MISSION ---{C.END}")
    send_discord_alert(f"Ares Mission Complete: {target_domain}", {"Status": "Finished", "Results": str(output_dir)}, "INFO")

if __name__ == "__main__":
    main()
