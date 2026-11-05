# BloxBean Java interoperability check

This local-only check builds the same public label-22092 test-vector batch with **BloxBean Cardano Client Lib 0.7.3**, signs and submits it to Yaci DevKit, then verifies the signed transaction with VitaLedger's TypeScript verifier. It demonstrates independent client interoperability; it does not replace the API's Lucid anchoring path.

```sh
interop/bloxbean/run.sh
```

The runner installs the pinned JDK and Maven, starts a fresh Yaci devnet, uses only the documented demo mnemonic at account index 4, and stops Yaci afterward. The store endpoint must be loopback HTTP. Output goes to ignored `.tools/` files. No Preprod/mainnet transaction is possible through this client.

The TypeScript check compares Yaci's raw transaction body with the body range in Java's full signed CBOR, then verifies the full signed bytes: transaction ID, auxiliary-data hash, metadata, record digest, and Merkle proof.
