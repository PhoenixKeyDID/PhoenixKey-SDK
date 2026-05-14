# did:phoenix Method Specification

**Version:** 1.0  
**Status:** Implementors Draft  
**Published:** 2026-05-12  
**Latest version:** https://phoenixkey.me/did-method/v1  
**Authors:** GreenSun Tech — contact@greensun.tech — https://greensun.tech  
**Repository:** https://github.com/PhoenixKeyDID  
**Conforms to:** [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)

---

## Abstract

The `did:phoenix` DID method anchors decentralized identifiers on the **Cardano blockchain** using the PhoenixKey protocol. It supports ten entity types — human, organization, device, machine, asset, bot, AI agent, digital service, context, and virtual character — with hardware-backed key security, tiered recovery without seed phrases, and optional cross-chain identity linking.

---

## 1. Method Name

```
did:phoenix
```

---

## 2. Method-Specific Identifier

```abnf
did-phoenix        = "did:phoenix:" slot-component ":" hash-component
slot-component     = 1*( ALPHA / DIGIT )   ; base32-encoded Cardano slot number
hash-component     = 64HEXDIG              ; BLAKE2b-256 hash, lowercase hex
```

**Construction:**

```
hash = BLAKE2b-256( encode(entity_type) || (owner_did ?? "root") || encode(slot) || random_256 )
did  = "did:phoenix:" || base32_nopad(slot) || ":" || hex(hash)
```

**Example:**
```
did:phoenix:aaaaaaq:3d7f9a1b2c4e56789012345678901234567890abcdef1234567890abcdef1234
```

---

## 3. DID Document

A `did:phoenix` DID Document is derived from the on-chain TAAD UTxO datum at resolution time. All documents MUST include the following context:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://phoenixkey.io/context/v1"
  ]
}
```

**Verification methods (PersonDID example):**

```json
{
  "id": "did:phoenix:SLOT:HASH",
  "controller": "did:phoenix:SLOT:HASH",
  "verificationMethod": [
    {
      "id": "did:phoenix:SLOT:HASH#hw-key-current",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:phoenix:SLOT:HASH",
      "publicKeyMultibase": "z...",
      "securityLevel": "BiometricHardware"
    },
    {
      "id": "did:phoenix:SLOT:HASH#taad-key-current",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:phoenix:SLOT:HASH",
      "publicKeyMultibase": "z..."
    }
  ],
  "authentication":        ["did:phoenix:SLOT:HASH#hw-key-current"],
  "assertionMethod":       ["did:phoenix:SLOT:HASH#hw-key-current"],
  "capabilityInvocation":  ["did:phoenix:SLOT:HASH#taad-key-current"],
  "capabilityDelegation":  ["did:phoenix:SLOT:HASH#taad-key-current"],
  "service": [
    {
      "id": "did:phoenix:SLOT:HASH#taad",
      "type": "PhoenixKeyTAAD",
      "serviceEndpoint": {
        "network": "cardano:mainnet",
        "utxoTxHash": "...",
        "utxoIndex": 0
      }
    }
  ]
}
```

Non-human DIDs (OrgDID, DeviceDID, etc.) use the same structure with the owner's DID as `controller` and method-appropriate verification methods. Full examples: https://phoenixkey.me/did-method/v1/examples

---

## 4. CRUD Operations

### 4.1 Create

1. Generate Ed25519 key pair in device Secure Enclave (`HW_Key`) and derive `TAAD_Key` from `Master_KEK`.
2. Compute `did` using the construction formula in §2.
3. Submit a Cardano transaction creating a TAAD UTxO at `Script(TAAD_Validator)` with a datum containing the DID, controller key hash, hardware public key, and initial state `Active`.
4. DID is live after 3 block confirmations on Cardano mainnet.

### 4.2 Read (Resolve)

1. Parse `did:phoenix:SLOT:HASH` to extract slot and hash.
2. Query Cardano for the UTxO at `Script(TAAD_Validator)` whose datum matches the DID.
3. **MUST** traverse the full ancestor ownership chain; if any ancestor is revoked or suspended, return `"deactivated": true`.
4. Construct and return the DID Document from the datum fields.

### 4.3 Update

- **Key rotation:** Initiated via the TAAD tiered recovery protocol. A new hardware key is committed on-chain after a timelock period (7–14 days). The DID string does not change; verification methods update to reflect the new keys.
- **Guardian or service update:** Requires a signature from the current hardware key. Recorded on-chain by spending and reissuing the TAAD UTxO with an incremented sequence number.

### 4.4 Deactivate

Submit a Cardano transaction setting `revoked_slot` in the TAAD datum. Requires current hardware key signature. Deactivation is **permanent and irreversible**. All descendant DIDs are implicitly deactivated (lazy cascade: resolvers MUST check ancestry on every resolution).

---

## 5. Security Considerations

- **Hardware-bound keys.** The `hw-key` private key is generated in and permanently bound to a device Secure Enclave (Apple SEP / Android StrongBox). It cannot be exported.
- **Replay prevention.** Every TAAD state transition increments a monotonic sequence number enforced by the on-chain validator. Transactions with `seq ≤ on-chain seq` are rejected.
- **Guardian suspension.** Guardians may suspend a DID, but cancel and recovery operations bypass the suspension check, preventing permanent lockout.
- **Recovery security.** No PPT adversary can forge a valid key-rotation transaction without the current hardware key, a threshold of guardian signatures, or breaking Ed25519 / BLAKE2b-256.
- **Ancestor deactivation.** Resolvers MUST walk the full ownership ancestry. A child DID cannot be considered active if any ancestor is deactivated.

---

## 6. Privacy Considerations

- No personally identifiable information is stored in the DID or on-chain datum. Biometric data is stored only as a hash; raw biometric data is never on-chain.
- `alsoKnownAs` cross-chain links are **user-initiated** and constitute a public, permanent assertion of identity equivalence. Users should understand this before adding links.
- TAAD UTxO spending history is publicly visible on Cardano and can be used to reconstruct a DID's activity timeline. This is inherent to any blockchain-anchored DID method.
- Resolver operators may log resolution requests. Users requiring query privacy should operate their own resolver node.

---

## 7. Reference Implementation

| Component | URL |
|-----------|-----|
| Full method specification | https://phoenixkey.me/did-method/v1/full |
| TAAD Validator (Plutus V3) | https://github.com/PhoenixKeyDID/phoenixkey-validator |
| Resolver (Node.js) | https://github.com/PhoenixKeyDID/did-phoenix-resolver |
| Universal Resolver Driver | https://github.com/PhoenixKeyDID/uni-resolver-driver-did-phoenix |
| JSON-LD Context | https://phoenixkey.me/context/v1 |
| Mathematical Specification | https://phoenixkey.me/spec/math/v4.2 |

---

*© 2026 GreenSun Tech Corporation — Apache 2.0 License*  
*contact@greensun.tech — https://greensun.tech*
