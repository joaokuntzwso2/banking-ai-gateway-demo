# Upgrade to v2.2.0

## 1. Back up v2.1.x

```bash
cd "$HOME/wso2-ai-security-demo"
mv bank-ai-security-console "bank-ai-security-console.backup.$(date +%Y%m%d-%H%M%S)"
mv modular-ai-guardrails "modular-ai-guardrails.backup.$(date +%Y%m%d-%H%M%S)"
tar -xzf ~/Downloads/wso2-bank-ai-security-complete-v2.2.0.tgz
```

Restore the newest UI `.env` explicitly:

```bash
BACKUP_DIR="$(find . -maxdepth 1 -type d -name 'bank-ai-security-console.backup.*' -print | sort -r | head -n 1)"
cp "$BACKUP_DIR/.env" bank-ai-security-console/.env
```

## 2. Deploy the expanded modular chain

```bash
cd modular-ai-guardrails
export DEMO_HOME="$HOME/wso2-ai-security-demo"
export GATEWAY_HOME="$DEMO_HOME/wso2apip-ai-gateway-1.1.0"
export DEMO_DELEGATION_CONTEXT_SECRET='replace-with-at-least-24-characters'

./scripts/install-sources.sh
./scripts/build-and-restart.sh
./scripts/apply-policy-chain.sh
```

## 3. Synchronize and start the UI

```bash
cd ../bank-ai-security-console
export DEMO_DELEGATION_CONTEXT_SECRET='replace-with-the-same-value'
./scripts/sync-api-key.sh
npm install
npm test
npm run dev
```

The same delegation secret must be used by the deployed agent policy and BFF. A fresh proxy key is generated after the policy update.
