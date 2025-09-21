# Hoodi Spammer (Node.js)

Spam either the **private builder** (all slots or compliance-filtered) or the **public mempool**.

- **Private mode**: fetches the validator schedule and:
  - if `complianceFilter` is set → targets only those slots  
  - if not set → targets **all upcoming slots** (capped by `maxSlotsPerCycle`)  
  - waits until the **pre-slot window** and submits bundles for that slot’s **target block** every `bundleIntervalMs` until the block appears.
- **Public mode**: sends one raw transaction per block, replacing nonce until time limit.

---

## Requirements
- Node.js **18+**
- `npm`

---

## Installation
Clone the repo and install dependencies:

```bash
git clone git@github.com:jessenia/eth-mempool-spammer.git
cd eth-mempool-spammer
npm install
```

---

## Environment Setup

Secrets and connection details go in an environment file.

1. Copy the example file:
```bash
cp .env.example .env
```

2. Fill in your values.

### Example `.env.example`
```dotenv
READ_RPC_URL=https://hoodi.infura.io/v3/<YOUR_API_KEY>
PRIVATE_RELAY_URL=https://<YOUR_RELAY_HOST>:8645
WALLET_PRIVATE_KEY=0x<YOUR_PRIVATE_KEY>
RECIPIENT_ADDRESS=0x<TARGET_ADDRESS>
AUTH_HEADER=Bearer <OPTIONAL_TOKEN>
```

### `.gitignore`
```gitignore
.env
.env.local
node_modules/
*.log
```

---

## Running the Tool

### Public mempool
```bash
node src/hoodi_spammer.js -c config/config.public.json
```

### Private builder
```bash
node src/hoodi_spammer.js -c config/config.private.json
```

### With time limit (seconds)
```bash
node src/hoodi_spammer.js -c config/config.private.json --duration 900
```

Exit codes:
- **0** → at least one transaction included  
- **2** → none included before timeout  

---

## Config Files

Example `config/config.private.json`:

```json
{
  "mode": "private",
  "readRpcUrl": "${READ_RPC_URL}",
  "privateRelayUrl": "${PRIVATE_RELAY_URL}",
  "privateKey": "${WALLET_PRIVATE_KEY}",
  "expectedChainId": 560048,
  "recipientAddress": "${RECIPIENT_ADDRESS}",
  "transferAmountEth": "0.001",
  "ethGasLimit": 200000,
  "asset": "WETH",
  "wethAddress": "0x2387fD72C1DA19f6486B843F5da562679FbB4057",
  "erc20GasLimit": 150000,
  "wrapGasLimit": 70000,
  "wrapIfNeeded": true,
  "minPriorityFeeGwei": 10000,
  "runDurationSecs": 900,
  "httpTimeoutSecs": 6,
  "validatorListUrl": "${PRIVATE_RELAY_URL}/relay/v1/builder/validators"
}
```

Values like `${READ_RPC_URL}` are replaced from your `.env`.


