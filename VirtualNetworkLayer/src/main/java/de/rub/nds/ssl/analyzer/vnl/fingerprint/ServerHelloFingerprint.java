package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.analyzer.vnl.Connection;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.Serializer;
import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.ECompressionMethod;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.Id;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.Extensions;

import java.util.ArrayList;
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

        Extensions extensions = serverHello.getExtensions();

        addSign("extensions-layout", extensions.getRawExtensionTypes());

        //TODO: extensions content
    }

    @Override
    public void deserialize(String serialized) {
        String[] signs = serialized.split(SERIALIZATION_DELIMITER, -1);
        if(signs.length != 5) {
            throw new IllegalArgumentException("Serialized form of fingerprint invalid: "
                    + "Wrong sign count " + signs.length);
        }

        byte[] bytes;
        bytes = Utility.hexToBytes(signs[0].trim());
        addSign("version", EProtocolVersion.getProtocolVersion(bytes));

        bytes = Utility.hexToBytes(signs[1].trim());
        addSign("cipher-suite", ECipherSuite.getCipherSuite(bytes));

        bytes = Utility.hexToBytes(signs[2].trim());
        addSign("compression-method", ECompressionMethod.getCompressionMethod(bytes[0]));

        addSign("session-id-empty", signs[3].trim().equals("true"));

        List<Id> extensionLayout = new ArrayList<>();
        for(Id id : Serializer.deserializeList(signs[4].trim())) {
            extensionLayout.add(id);
        }
        addSign("extensions-layout", extensionLayout);
    }
}
