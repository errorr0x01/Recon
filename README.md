# Automated Reconnaissance and Vulnerability Scanner

This is a powerful, all-in-one reconnaissance script that automates a modern security workflow. It orchestrates a suite of best-in-class open-source tools to discover and analyze a target's attack surface, from initial discovery to vulnerability scanning, with real-time Slack alerts for critical findings.

## Features

-   **Multi-Source Discovery**: Gathers assets from Shodan (via a custom scraper), subdomains (`subfinder`), historical archives (`gau`), and GitHub (`gitleaks`).
-   **Contextual Analysis**: Identifies live web servers (`httpx`), detects their technology stacks, and performs visual reconnaissance with screenshots (`gows`).
-   **In-Depth Scanning**: Conducts port scanning (`naabu`), collects JavaScript files and endpoints (`katana`), and scans for vulnerabilities (`nuclei`).
-   **Secret Detection**: Scans both JavaScript files and public GitHub repositories for leaked API keys, tokens, and other credentials.
-   **Fully Automated**: Executes the entire complex pipeline with a single command.
-   **Real-Time Alerts**: Sends detailed notifications to a Slack webhook for high-impact findings.
-   **Organized Output**: Creates a unique, timestamped directory for each scan to keep results organized.

## Prerequisites

You must install all of the following tools and ensure they are available in your system's `PATH`.

```bash
# Install Go language first: https://go.dev/doc/install

# Install Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/goretk/gows/cmd/gows@latest
go install -v github.com/gitleaks/gitleaks/v8@latest

# Update Nuclei templates to the latest version
nuclei -update-templates

# Other dependencies (jq, curl)
# On Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y jq curl
# On macOS: brew install jq curl
```

## Usage

1.  Clone this repository or download the `ultimate_recon.py` script.
2.  Make the script executable:
    ```bash
    chmod +x ultimate_recon.py
    ```
3.  Run the scan with your target domain and optional Slack webhook:
    ```bash
    ./ultimate_recon.py -d example.com -w "https://hooks.slack.com/services/T000.../B000.../XXXXXXXX"
    ```
    -   `-d` or `--domain`: The root domain to scan.
    -   `-w` or `--webhook`: (Optional) Your Slack webhook for alerts.

## Disclaimer

This tool is intended for educational purposes and authorized security assessments only. Running this script against systems you do not have explicit permission to test is illegal. The author is not responsible for any misuse or damage caused by this script.
