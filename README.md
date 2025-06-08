```bash
# First, ensure you have the Go language installed:
# https://go.dev/doc/install

# Install the required Go-based tools
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

# Update Nuclei templates to the latest version
nuclei -update-templates

# Install Graphviz on your system for visualization
# On Debian/Ubuntu:
sudo apt-get update && sudo apt-get install graphviz

# On macOS:
brew install graphviz

# Install required Python libraries
pip install requests mmh3 graphviz

# Usage

# Configure the Discord Webhook:
# Open ares_engine.py and replace "YOUR_DISCORD_WEBHOOK_URL_GOES_HERE" with your actual Discord webhook URL.

# Make the script executable:
chmod +x ares_engine.py

# Run the Engine:
# You must acknowledge that you have permission to test the target by using the --i-have-permission flag.

# Run a full offensive scan
./ares_engine.py -d example.com --i-have-permission

# Run in reconnaissance-only mode (no attacks)
./ares_engine.py -d example.com --i-have-permission --dry-run
