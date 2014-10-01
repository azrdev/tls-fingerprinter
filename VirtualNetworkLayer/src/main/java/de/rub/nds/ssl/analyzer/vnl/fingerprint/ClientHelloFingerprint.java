package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.analyzer.vnl.Connection;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.Serializer;
import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.Id;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.Extensions;

import java.util.ArrayList;
import java.util.List;

public class ClientHelloFingerprint extends Fingerprint {

    public ClientHelloFingerprint(String serialized) {
        deserialize(serialized);
    }

    public ClientHelloFingerprint(Connection connection) {
        this(connection.getClientHello());
    }

    public ClientHelloFingerprint(ClientHello clientHello) {
        if(clientHello == null)
            throw new NotMatchingException();

        addSign("version", clientHello.getProtocolVersion());
        addSign("session-id-empty", clientHello.getSessionID().isEmpty());

        //TODO: make fuzzy
        addSign("compression-method-list",
                clientHello.getCompressionMethod().getRawMethods());
        addSign("cipher-suite-list",
                clientHello.getCipherSuites().getRawSuites());

        Extensions extensions = clientHello.getExtensions();

        addSign("extensions-layout", extensions.getRawExtensionTypes());

        //TODO: extensions content
    }

    @Override
    public void deserialize(String serialized) throws IllegalArgumentException {
        String[] signs = serialized.trim().split(SERIALIZATION_DELIMITER, -1);
        if(signs.length != 5) {
            throw new IllegalArgumentException("Serialized form of fingerprint invalid: "
                    + "Wrong sign count " + signs.length);
        }

        byte[] bytes;
        bytes = Utility.hexToBytes(signs[0].trim());
        addSign("version", EProtocolVersion.getProtocolVersion(bytes));

        addSign("session-id-empty", signs[1].trim().equals("true"));

        List<Id> compressionMethods = new ArrayList<>();
        for(Id id : Serializer.deserializeList(signs[2].trim())) {
            compressionMethods.add(id);
        }
        addSign("compression-method-list", compressionMethods);

        List<Id> cipherSuites = new ArrayList<>();
        for(Id id : Serializer.deserializeList(signs[3].trim())) {
            cipherSuites.add(id);
        }
        addSign("cipher-suite-list", cipherSuites);

        List<Id> extensionLayout = new ArrayList<>();
        for(Id id : Serializer.deserializeList(signs[4].trim())) {
            extensionLayout.add(id);
        }
        addSign("extensions-layout", extensionLayout);
    }
}
