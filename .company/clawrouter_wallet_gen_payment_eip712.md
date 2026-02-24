# Wallet Generation and EIP-712 Payment Signing

## 1. Wallet Generation

**Where:** `src/auth.ts`

**Resolution order:** saved file → env var → generate and save.

1. **Saved wallet**
   - Read `~/.openclaw/blockrun/wallet.key`.
   - If it exists and is valid (starts with `0x`, length 66, hex), use it and derive address with `privateKeyToAccount(saved)`.

2. **Environment**
   - If `BLOCKRUN_WALLET_KEY` is set and looks like a 66-char hex key (`0x` + 64 hex), use it and derive address.

3. **Generate and save**
   - Call `generatePrivateKey()` from `viem/accounts` (random 32-byte key, 64 hex chars + `0x`).
   - Derive address with `privateKeyToAccount(key)`.
   - Ensure `~/.openclaw/blockrun` exists (`mkdir(..., { recursive: true })`).
   - Write the key to `wallet.key` with mode `0o600`.
   - Re-read the file and assert content equals the generated key (verification).
   - Return `{ key, address }`.

```typescript
// auth.ts (excerpt)
async function generateAndSaveWallet(): Promise<{ key: string; address: string }> {
  const key = generatePrivateKey();
  const account = privateKeyToAccount(key);

  await mkdir(WALLET_DIR, { recursive: true });
  await writeFile(WALLET_FILE, key + "\n", { mode: 0o600 });

  const verification = (await readFile(WALLET_FILE, "utf-8")).trim();
  if (verification !== key) {
    throw new Error("Wallet file verification failed - content mismatch");
  }

  return { key, address: account.address };
}
```

So: wallet = viem `generatePrivateKey()`; address = `privateKeyToAccount(key).address`; optional persist to `~/.openclaw/blockrun/wallet.key` with verification.

---

## 2. Client Signing Payment Authorization (EIP-712)

**Where:** `src/x402.ts`

The client does **not** sign a generic “Payment” type. It signs USDC’s **TransferWithAuthorization** (EIP-3009) typed data so the recipient can pull USDC from the signer’s wallet.

**Steps:**

1. **Get payment parameters**  
   From the 402 response (or from cache for pre-auth): `scheme`, `network`, `asset` (USDC contract), `payTo` (recipient), `amount` (or `maxAmountRequired`), optional `extra.name` / `extra.version`, `maxTimeoutSeconds`.

2. **Resolve domain and chain**
   - `network` is normalized (e.g. `"base"` → `eip155:8453`).
   - `chainId` = 8453 (Base) or 84532 (Base Sepolia) from `network`.
   - `verifyingContract` = `option.asset` (USDC contract address).
   - Domain name/version = `option.extra?.name/version` or defaults `"USD Coin"` / `"2"`.

3. **Build EIP-712 message**
   - `from`: signer (wallet address).
   - `to`: `option.payTo` (recipient).
   - `value`: `BigInt(amount)` (USDC 6 decimals).
   - `validAfter`: `now - 600`.
   - `validBefore`: `now + maxTimeoutSeconds` (cap 300s default).
   - `nonce`: 32 random bytes as `0x` + 64 hex (from `crypto.getRandomValues`).

4. **Sign with viem**  
   `signTypedData` from `viem/accounts` is called with:
   - `privateKey`: wallet key (from auth above).
   - `domain`: `{ name, version, chainId, verifyingContract }`.
   - `types`: `TRANSFER_TYPES` (see below).
   - `primaryType`: `"TransferWithAuthorization"`.
   - `message`: the from/to/value/validAfter/validBefore/nonce object.

```typescript
// x402.ts – EIP-712 types
const TRANSFER_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

// Signing call
const signature = await signTypedData({
  privateKey,
  domain: {
    name: option.extra?.name || DEFAULT_TOKEN_NAME,
    version: option.extra?.version || DEFAULT_TOKEN_VERSION,
    chainId,
    verifyingContract,
  },
  types: TRANSFER_TYPES,
  primaryType: "TransferWithAuthorization",
  message: {
    from: fromAddress,
    to: recipient,
    value: BigInt(amount),
    validAfter: BigInt(validAfter),
    validBefore: BigInt(validBefore),
    nonce,
  },
});
```

5. **Wrap and send**  
   The signature and authorization fields are put into a payload (x402Version 2, resource, accepted, payload.signature + authorization, extensions), JSON-serialized, base64-encoded, and set on the request as `Payment-Signature` and `X-Payment` headers. The proxy uses this in the normal 402 flow and in the pre-auth path (cached params + estimated amount) when calling BlockRun.

So: the client signs a **single EIP-712 typed message** (USDC `TransferWithAuthorization`) with its wallet key; that signed authorization is what the client sends as the “payment authorization” for x402.
