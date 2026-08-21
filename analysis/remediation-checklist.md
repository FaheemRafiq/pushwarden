# Malware Remediation Checklist

## CRITICAL: Do This First (Within 1 Hour)

### 1. Isolate the Machine
- [ ] Disconnect from WiFi/Ethernet immediately
- [ ] Do NOT shut down (memory may contain active credentials)
- [ ] Do NOT log into any accounts from this machine

### 2. Identify Scope
- [ ] Run `git reflog --all -30` in every repo directory
- [ ] Check for `.bat` files: `find ~ -name "*.bat" 2>/dev/null`
- [ ] Check for suspicious processes: `ps aux | grep node`
- [ ] Check shell configs: `cat ~/.bashrc ~/.zshrc ~/.profile`
- [ ] Check for cron jobs: `crontab -l`

### 3. Revoke ALL Credentials (In This Order)
**Priority 1 - GitHub (most dangerous for lateral spread):**
- [ ] GitHub Personal Access Tokens -> https://github.com/settings/tokens
  - Revoke ALL tokens immediately
  - Generate new tokens with minimal scopes
- [ ] GitHub SSH keys -> https://github.com/settings/keys
  - Remove ALL SSH keys
  - Generate new keypair: `ssh-keygen -t ed25519`
- [ ] GitHub OAuth apps -> https://github.com/settings/applications
  - Revoke all authorized OAuth apps

**Priority 2 - Cloud & Crypto:**
- [ ] AWS access keys -> AWS IAM console
- [ ] GCP service account keys
- [ ] Azure service principal secrets
- [ ] Crypto wallet private keys (move funds to new wallet FIRST)
- [ ] Exchange API keys (Binance, Coinbase, Gate.io, etc.)
- [ ] Alchemy / Infura / QuickNode API keys

**Priority 3 - Everything Else:**
- [ ] npm tokens -> `npm token list` then revoke all
- [ ] Docker Hub tokens
- [ ] Database passwords
- [ ] API keys in `.env` files
- [ ] SMTP/email credentials
- [ ] SSH keys for servers
- [ ] VPN credentials
- [ ] Any other secrets in environment variables

### 4. Clean Infected Repos
For EACH infected repository:

```bash
# Check if infected
cd <repo>
python3 ~/Coding/threatscan/threat_scanner.py .

# If infected, identify the infection commit
git log --oneline --all | head -20
git reflog --all | head -30

# Option A: If you know the last clean commit
git reset --hard <last-clean-commit-hash>
git push --force origin --all

# Option B: Nuclear option - recreate repo
# 1. Clone a fresh copy from GitHub
# 2. Check it locally before pushing
# 3. Delete old repo on GitHub
# 4. Push clean copy
```

### 5. Remove Propagation Scripts
```bash
# Find and delete all .bat malware scripts
find ~ -name "temp_auto_push.bat" -delete 2>/dev/null
find ~ -name "temp_interactive_push.bat" -delete 2>/dev/null
find ~ -name "config.bat" -delete 2>/dev/null
find ~ -name "auto_push.bat" -delete 2>/dev/null

# Clean .gitignore entries
# Remove lines referencing .bat files from ALL .gitignore files
```

### 6. Check & Clean Shell Configs
```bash
# Check for injected persistence
grep -n "curl\|wget\|eval\|base64\|node -e\|global\['" ~/.bashrc
grep -n "curl\|wget\|eval\|base64\|node -e\|global\['" ~/.zshrc
grep -n "curl\|wget\|eval\|base64\|node -e\|global\['" ~/.profile

# If anything suspicious, remove those lines
```

### 7. Check & Clean Cron
```bash
crontab -l
# Remove any entries containing: font, cache, temp, /tmp, curl, wget, eval, base64, node
crontab -e  # edit and remove suspicious entries
```

### 8. Check Running Processes
```bash
ps aux | grep -E "node|python" | grep -v grep
# Kill any suspicious node processes
kill -9 <PID>

# Check for detached processes
ps -ef | grep -E "detached|node -e"
```

## After Cleanup (Within 24 Hours)

### 9. Verify All Repos Are Clean
```bash
# Run ThreatScan on every repo
for repo in ~/Coding/*/*/; do
    if [ -d "$repo/.git" ]; then
        echo "Scanning: $repo"
        python3 ~/Coding/threatscan/threat_scanner.py "$repo"
    fi
done
```

### 10. Monitor for Re-infection
- [ ] Enable ThreatScan CI on all repos (already done for A-Bot-backend and mentor-ai-landing)
- [ ] Watch for unexpected git pushes for 7 days
- [ ] Monitor GitHub notification emails for repo activity
- [ ] Check `git reflog` daily in active repos

### 11. Audit Commits
```bash
# Check what was pushed while compromised
# Look for commits with these messages:
git log --all --oneline --grep="update config"
git log --all --oneline --grep="fix build"
git log --all --oneline --grep="add postcss"
git log --all --oneline --grep="update dependencies"
git log --all --oneline --grep="chore: update"
```

### 12. Check GitHub Repos via Web UI
- [ ] Go to each repo on GitHub.com
- [ ] Compare files on web vs local
- [ ] Check for any commits you didn't make
- [ ] Look for any `.bat` files in the repo
- [ ] Check Settings > Webhooks for unauthorized webhooks

## Prevention Going Forward

### 13. Security Hardening
- [ ] Install pre-commit hook: `cp ~/Coding/threatscan/analysis/defensive-rules/pre-commit.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit`
- [ ] Enable 2FA on all accounts (GitHub, npm, cloud providers)
- [ ] Use hardware security keys where possible
- [ ] Never run `npm install` on untrusted packages without reviewing
- [ ] Check `package.json` for `preinstall`/`postinstall`/`prepare` scripts before installing
- [ ] Use `npm audit` regularly
- [ ] Pin dependencies to specific versions (avoid `^` and `~`)

### 14. Network Monitoring
- [ ] Block C2 IPs at firewall level
- [ ] Monitor for outbound connections to unusual IPs
- [ ] Use DNS filtering (Pi-hole, Cloudflare Gateway)
- [ ] Enable network monitoring tools

### 15. File Integrity Monitoring
- [ ] Set up file integrity monitoring on config files
- [ ] Use `git diff` before every push
- [ ] Review changes to `postcss.config.js`, `tailwind.config.js`, etc. carefully
