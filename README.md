## 🚀 Installation

Project Ares orchestrates a suite of powerful, best-in-class open-source tools. You must install all of the following components and ensure they are available in your system's `PATH` before running the engine.

### 1. Install Go

First, ensure you have the **Go** programming language (version 1.18 or later) installed on your system.

> **Note:** You can find official installation instructions at: [https://go.dev/doc/install](https://go.dev/doc/install)

### 2. Install Go-based Tools

Once Go is set up, run the following commands one-by-one to install the core components of the Ares arsenal:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/goretk/gows/cmd/gows@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/devanshbatham/paramspider/cmd/paramspider@latest
go install -v github.com/tomnomnom/unfurl@latest
```

### 3. Update Nuclei Templates

It is crucial to have the latest vulnerability and detection templates. Run the following command to download the latest set from ProjectDiscovery.

```bash
nuclei -update-templates
```

### 4. Install Graphviz

This system-level package is required for generating the visual attack path graphs.

*   **On Debian/Ubuntu:**
    ```bash
    sudo apt-get update && sudo apt-get install -y graphviz
    ```

*   **On macOS (using Homebrew):**
    ```bash
    brew install graphviz
    ```

### 5. Install Python Libraries

Finally, install the required Python packages using pip.

```bash
pip install requests mmh3 graphviz
```

---

## ⚔️ Usage

### 1. Configure Discord Alerts

Before running, you must add your Discord webhook to the script. Open `ares_engine.py` in a text editor and replace the placeholder URL.

```python
"DISCORD_WEBHOOK_URL": "YOUR_DISCORD_WEBHOOK_URL_GOES_HERE",
```
> **Warning:** Never commit this file with your real webhook URL to a public GitHub repository.

### 2. Make the Script Executable

In your terminal, give the Ares script execution permissions.

```bash
chmod +x ares_engine.py
```

### 3. Run the Engine

You **must** acknowledge that you have permission to test the target by using the `--i-have-permission` flag. Ares will refuse to run without it.

#### To run a full offensive scan:
This will perform all reconnaissance, analysis, and attack phases, including the Threat Propagation Engine.

```bash
./ares_engine.py -d example.com --i-have-permission
```

#### To run in reconnaissance-only mode:
This will perform all discovery and analysis phases but will **not** run any offensive Nuclei scans. This is useful for safely mapping out a target.

```bash
./ares_engine.py -d example.com --i-have-permission --dry-run
```
