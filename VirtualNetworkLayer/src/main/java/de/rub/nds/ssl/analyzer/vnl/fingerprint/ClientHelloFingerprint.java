package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.analyzer.vnl.Connection;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.AExtension;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ClientHelloFingerprint extends Fingerprint {
    @Override
    protected void apply(Signature signature, Connection connection) {
        ClientHello clientHello = connection.getClientHello();

        signature.addSign("version", clientHello.getProtocolVersion());
        signature.addSign("session-id-empty", clientHello.getSessionID().isEmpty());

        //TODO: make fuzzy
        signature.addSign("compression-method-list",
                clientHello.getCompressionMethod().getMethods());
        signature.addSign("cipher-suite-list",
                Arrays.asList(clientHello.getCipherSuites()));

        AExtension[] extensions = clientHello.getExtensions().getExtensions();

        List<EExtensionType> extensionLayout = new ArrayList<>(extensions.length);
        for(AExtension extension : extensions) {
            extensionLayout.add(extension.getExtensionType());
        }
        signature.addSign("extensions-layout", extensionLayout);

        //TODO: extensions content
    }

    @Override
    public boolean canApply(Connection connection) {
        return connection.getClientHello() != null;
    }

    @Override
    public List<String> serializedSigns() {
        return Arrays.asList(
                "version",
                "session-id-empty",
                "compression-method-list",
                "cipher-suite-list",
                "extensions-layout");
    }
}
