package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.analyzer.vnl.Connection;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.Serializer;
import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.ECompressionMethod;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.AExtension;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import de.rub.nds.virtualnetworklayer.util.Util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ClientHelloFingerprint extends Fingerprint {

    public ClientHelloFingerprint(String serialized) {
        deserialize(serialized);
    }

    public ClientHelloFingerprint(Connection connection) {
        ClientHello clientHello = connection.getClientHello();
        if(clientHello == null)
            throw new NotMatchingException();

        addSign("version", clientHello.getProtocolVersion());
        addSign("session-id-empty", clientHello.getSessionID().isEmpty());

        //TODO: make fuzzy
        addSign("compression-method-list",
                clientHello.getCompressionMethod().getMethods());
        addSign("cipher-suite-list",
                Arrays.asList(clientHello.getCipherSuites()));

        AExtension[] extensions = clientHello.getExtensions().getExtensions();

        List<EExtensionType> extensionLayout = new ArrayList<>(extensions.length);
        for(AExtension extension : extensions) {
            extensionLayout.add(extension.getExtensionType());
        }
        addSign("extensions-layout", extensionLayout);

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
