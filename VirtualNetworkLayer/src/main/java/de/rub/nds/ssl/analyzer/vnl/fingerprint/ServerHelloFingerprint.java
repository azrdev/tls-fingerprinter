package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.analyzer.vnl.Connection;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.AExtension;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ServerHelloFingerprint extends Fingerprint {

    @Override
    public boolean canApply(Connection connection) {
        return connection.getServerHello() != null;
    }

    @Override
    public List<String> serializedSigns() {
        return Arrays.asList(
                "version",
                "cipher-suite",
                "compression-method",
                "session-id-empty",
                "extensions-layout");
    }

    @Override
    protected void apply(Signature signature, Connection connection) {
        ServerHello serverHello = connection.getServerHello();

        signature.addSign("version", serverHello.getProtocolVersion());
        signature.addSign("cipher-suite", serverHello.getCipherSuite());
        signature.addSign("compression-method", serverHello.getCompressionMethod());
        signature.addSign("session-id-empty", serverHello.getSessionID().isEmpty());

        AExtension[] extensions = serverHello.getExtensions().getExtensions();

        List<EExtensionType> extensionLayout = new ArrayList<>(extensions.length);
        for(AExtension extension : extensions) {
            extensionLayout.add(extension.getExtensionType());
        }
        signature.addSign("extensions-layout", extensionLayout);

        //TODO: extensions content
    }
}
