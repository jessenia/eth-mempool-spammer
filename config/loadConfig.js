function loadConfig(path) {
  let raw = fs.readFileSync(path, "utf8");

  // 2) substitute ${VAR} from process.env (fail fast if missing)
  raw = raw.replace(/\$\{(\w+)\}/g, (_, name) => {
    const v = process.env[name];
    if (v === undefined) {
      console.error(`Missing environment variable: ${name} (referenced in ${path})`);
      exit(1);
    }
    return v;
  });

  const cfg = JSON.parse(raw);

  const required = [
    "mode","readRpcUrl","privateKey","expectedChainId",
    "recipientAddress","transferAmountEth","ethGasLimit",
    "minPriorityFeeGwei","priorityFeeBufferGwei",
    "retryPriorityFeeBumpGwei","baseFeeMultiplier","httpTimeoutSecs"
  ];
  const missing = required.filter(k => cfg[k] === undefined);
  if (missing.length) {
    console.error(`Config missing: ${missing.join(", ")}`);
    exit(1);
  }

  cfg.mode = String(cfg.mode || "").toLowerCase();
  if (!["private","public"].includes(cfg.mode)) {
    console.error(`Config "mode" must be "private" or "public".`);
    exit(1);
  }

  cfg.asset = (cfg.asset || "ETH").toUpperCase();
  if (!["ETH","WETH"].includes(cfg.asset)) {
    console.error(`Config "asset" must be "ETH" or "WETH".`);
    exit(1);
  }

  cfg.recipientAddress = normalizeAddress(cfg.recipientAddress, "recipientAddress");
  if (cfg.asset === "WETH") {
    if (!cfg.wethAddress) {
      console.error(`Config error: asset "WETH" requires "wethAddress".`);
      exit(1);
    }
    cfg.wethAddress = normalizeAddress(cfg.wethAddress, "wethAddress");
    cfg.erc20GasLimit ??= 150000;
    cfg.wrapGasLimit  ??= 70000;
    cfg.wrapIfNeeded  ??= true;
  }

  if (cfg.mode === "private") {
    cfg.privateRelayUrl = cfg.privateRelayUrl || cfg.builderUrl;
    if (!cfg.privateRelayUrl) {
      console.error(`Config error: mode "private" requires "privateRelayUrl".`);
      exit(1);
    }
    if (!cfg.validatorListUrl) {
      console.error(`Private mode requires "validatorListUrl".`);
      exit(1);
    }
  }

  cfg.authorizationHeader ??= null;
  cfg.runDurationSecs = Number.isFinite(Number(cfg.runDurationSecs)) ? Number(cfg.runDurationSecs) : null;
  cfg.compliancePollIntervalSecs ??= 12;
  cfg.slotOffset ??= 0;
  cfg.retryAttempts ??= 0;
  cfg.maxTxFeeEth ??= null;

  cfg.preSlotLeadMs ??= 1100;
  cfg.maxSlotsPerCycle ??= 8;
  cfg.idleRetryMs ??= 1200;
  cfg.relayPostTimeoutMs ??= 400;
  cfg.postBlockReceiptWaitMs ??= 7000;

  cfg.bundleIntervalMs ??= 3000;
  cfg.maxBundlesPerSlot ??= 0;

  cfg.beaconchainUrl ??= "https://hoodi.beaconcha.in/";
  cfg.beaconchainLightUrl ??= "https://light-hoodi.beaconcha.in/";
  cfg.doraUrl ??= "https://dora.hoodi.ethpandaops.io/";

  if (!String(cfg.privateKey).startsWith("0x")) cfg.privateKey = "0x" + cfg.privateKey;

  return cfg;
}
