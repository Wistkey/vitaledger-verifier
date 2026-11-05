package ai.vitababy.bloxbean;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.metadata.Metadata;
import com.bloxbean.cardano.client.metadata.MetadataBuilder;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.client.quicktx.TxResult;
import com.bloxbean.cardano.client.transaction.spec.Transaction;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

public final class AnchorInterop {
    private static final String DEVNET_MNEMONIC = ("test ".repeat(23) + "sauce").trim();
    private static final BigInteger LABEL = BigInteger.valueOf(22092);

    private AnchorInterop() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new IllegalArgumentException("usage: AnchorInterop <loopback-yaci-store-url> <v1.json> <output.json>");
        }
        String storeUrl = localStoreUrl(args[0]);
        Path vectorsPath = Path.of(args[1]).toAbsolutePath().normalize();
        Path outputPath = Path.of(args[2]).toAbsolutePath().normalize();
        ObjectMapper json = new ObjectMapper();
        JsonNode vectors = json.readTree(Files.readString(vectorsPath));
        JsonNode firstRecord = vectors.at("/records/0");
        JsonNode metadataBody = vectors.at("/batch/metadata/22092");
        if (firstRecord.isMissingNode() || metadataBody.isMissingNode()) {
            throw new IllegalArgumentException("test vector has no first record or label-22092 batch metadata");
        }

        Metadata metadata = MetadataBuilder.metadataFromJsonBody(LABEL, metadataBody.toString());
        Account account = Account.createFromMnemonic(Networks.testnet(), DEVNET_MNEMONIC, 4, 0);
        BackendService backend = new BFBackendService(storeUrl, "yaci-devkit");
        AtomicReference<Transaction> signed = new AtomicReference<>();
        Tx tx = new Tx()
                .payToAddress(account.baseAddress(), Amount.ada(1))
                .attachMetadata(metadata)
                .from(account.baseAddress());
        TxResult result = new QuickTxBuilder(backend)
                .compose(tx)
                .withSigner(SignerProviders.signerFrom(account))
                .withTxInspector(signed::set)
                .complete();
        if (!result.isSuccessful()) {
            throw new IllegalStateException("Yaci rejected the BloxBean transaction: " + result);
        }
        String txHash = result.getValue();
        ObjectNode output = json.createObjectNode();
        output.put("txHash", txHash);
        output.put("cborHex", signed.get().serializeToHex());
        output.set("bundle", json.createObjectNode()
                .set("record", firstRecord.get("record")));
        ((ObjectNode) output.get("bundle")).set("proof", firstRecord.get("proof"));
        ObjectNode anchor = ((ObjectNode) output.get("bundle")).putObject("anchor");
        // The bundle format only knows preprod/mainnet; the tx is on the local Yaci devnet
        // (testnet magic), and verify.ts checks it there via Yaci Store, not Preprod.
        anchor.put("network", "preprod");
        anchor.put("txHash", txHash);
        anchor.put("label", 22092);
        Path parent = outputPath.getParent();
        if (parent != null) Files.createDirectories(parent);
        Files.writeString(outputPath, json.writerWithDefaultPrettyPrinter().writeValueAsString(output) + "\n");
        System.out.println("BloxBean transaction submitted: " + txHash);
        System.out.println("Verifier input: " + outputPath);
    }

    private static String localStoreUrl(String value) {
        URI uri = URI.create(value);
        if (!"http".equals(uri.getScheme()) || !Set.of("127.0.0.1", "localhost", "[::1]").contains(uri.getHost())) {
            throw new IllegalArgumentException("only a loopback HTTP Yaci Store endpoint is allowed");
        }
        return value.replaceAll("/+$", "") + "/";
    }
}
