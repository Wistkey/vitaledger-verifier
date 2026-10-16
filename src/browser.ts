/** Browser entry: exposes the verifier as the global `VitaLedgerVerifier`. */
export { verifyAgainstTransaction } from "./verify.js";
export { recordDigest } from "./digest.js";
export { explorerUrl } from "./chain.js";
export { VITALEDGER_LABEL } from "./metadata.js";
export { checkIssuer, readRegistryEntry, registryTokenName, REGISTRY } from "./registry.js";
export { publicKeyFromCoseKey, verifyMessageSignature } from "./cip8.js";
export { signedMessage } from "./signed-message.js";
