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
    public void deserialize(String serialized) {
        String[] signs = serialized.trim().split(SERIALIZATION_DELIMITER, -1);
        if(signs.length != 5) {
            throw new IllegalArgumentException("Serialized form of fingerprint invalid: "
                    + "Wrong sign count " + signs.length);
        }

        byte[] bytes;
        bytes = Utility.hexToBytes(signs[0].trim());
        addSign("version", EProtocolVersion.getProtocolVersion(bytes));

        addSign("session-id-empty", signs[1].trim().equals("true"));

        List<ECompressionMethod> compressionMethods = new ArrayList<>();
        for(byte[] b : Serializer.deserializeList(signs[2].trim())) {
            try {
                // should be only one byte, ignore others
                compressionMethods.add(ECompressionMethod.getCompressionMethod(b[0]));
            } catch (IllegalArgumentException e) {
                // best effort
                compressionMethods.add(null);
            }
        }
        addSign("compression-method-list", compressionMethods);

        List<ECipherSuite> cipherSuites = new ArrayList<>();
        for(byte[] b : Serializer.deserializeList(signs[3].trim())) {
            try {
                cipherSuites.add(ECipherSuite.getCipherSuite(b));
            } catch(IllegalArgumentException e) {
                // best effort
                cipherSuites.add(null);
            }
        }
        addSign("cipher-suite-list", cipherSuites);

        List<EExtensionType> extensionLayout = new ArrayList<>();
        for(byte[] b : Serializer.deserializeList(signs[4].trim())) {
            try {
                extensionLayout.add(EExtensionType.getExtension(b));
            } catch(IllegalArgumentException e) {
                // best effort
                extensionLayout.add(null);
            }
        }
        addSign("extensions-layout", extensionLayout);
    }
}
