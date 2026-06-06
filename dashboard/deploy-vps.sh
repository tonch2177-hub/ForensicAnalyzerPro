#!/bin/bash
# ForensicAnalyzer Dashboard — VPS Deployment
# Usage: bash deploy-vps.sh

set -e

echo "=== ForensicAnalyzer Dashboard VPS Setup ==="

# 1. Install Node.js if missing
if ! command -v node &> /dev/null; then
    echo "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs
fi

# 2. Install dependencies
cd "$(dirname "$0")"
echo "Installing npm packages..."
npm install

# 3. Configure
echo ""
echo "Edit config.json with your Discord webhook URL:"
echo "  nano config.json"

# 4. Start with PM2
if ! command -v pm2 &> /dev/null; then
    npm install -g pm2
fi

echo ""
echo "Starting with PM2..."
pm2 start server.js --name forensic-dashboard
pm2 save

# 5. Setup auto-start on reboot
pm2 startup | tail -1
echo ""
echo "=== Done! Dashboard running on http://localhost:3000 ==="
echo "Use: pm2 logs forensic-dashboard  — to see logs"
echo "Use: pm2 restart forensic-dashboard — to restart"
