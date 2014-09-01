package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.analyzer.vnl.Connection;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.Serializer;
import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.ECompressionMethod;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.AExtension;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ServerHelloFingerprint extends Fingerprint {

    public ServerHelloFingerprint(String serialized) {
        deserialize(serialized);
    }

    public ServerHelloFingerprint(Connection connection) {
        ServerHello serverHello = connection.getServerHello();
        if(serverHello == null)
            throw new NotMatchingException();

        addSign("version", serverHello.getProtocolVersion());
        addSign("cipher-suite", serverHello.getCipherSuite());
        addSign("compression-method", serverHello.getCompressionMethod());
        addSign("session-id-empty", serverHello.getSessionID().isEmpty());

        AExtension[] extensions = serverHello.getExtensions().getExtensions();

        List<EExtensionType> extensionLayout = new ArrayList<>(extensions.length);
        for(AExtension extension : extensions) {
            extensionLayout.add(extension.getExtensionType());
        }
        addSign("extensions-layout", extensionLayout);

        //TODO: extensions content
    }
}
