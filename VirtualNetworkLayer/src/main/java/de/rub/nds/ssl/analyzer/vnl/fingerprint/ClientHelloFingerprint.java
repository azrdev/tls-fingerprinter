package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import de.rub.nds.ssl.analyzer.vnl.Connection;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.Serializer;
import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.Id;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.Extensions;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.EllipticCurves;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.SupportedPointFormats;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;

import java.util.ArrayList;
import java.util.Arrays;
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

        // below are handled specific extensions, if present

        SupportedPointFormats supportedPointFormats =
                extensions.getExtension(EExtensionType.EC_POINT_FORMATS);
        if(supportedPointFormats != null) {
            addSign("supported-point-formats",
                    supportedPointFormats.getSupportedPointFormatsList());
        }

        EllipticCurves supportedCurves =
                extensions.getExtension(EExtensionType.ELLIPTIC_CURVES);
        if(supportedCurves != null) {
            addSign("supported-curves", supportedCurves.getSupportedCurvesList());
        }
    }

    @Override
    public List<String> serializationSigns() {
        return Arrays.asList("version",
                "session-id-empty",
                "compression-method-list",
                "cipher-suite-list",
                "extensions-layout",
                "supported-point-formats",
                "supported-curves");
    }

    @Override
    public void deserialize(String serialized) throws IllegalArgumentException {
        String[] signs = serialized.trim().split(SERIALIZATION_DELIMITER, -1);
        if(signs.length < 5) {
            throw new IllegalArgumentException("Serialized form of fingerprint invalid: "
                    + "Wrong sign count " + signs.length);
        }

        byte[] bytes;
        bytes = Utility.hexToBytes(signs[0].trim());
        addSign("version", EProtocolVersion.getProtocolVersion(bytes));

        addSign("session-id-empty", Serializer.deserializeBoolean(signs[1]));

        List<Id> compressionMethods = Serializer.deserializeList(signs[2].trim());
        addSign("compression-method-list", compressionMethods);

        List<Id> cipherSuites = Serializer.deserializeList(signs[3].trim());
        addSign("cipher-suite-list", cipherSuites);

        List<Id> extensionLayout = Serializer.deserializeList(signs[4].trim());
        addSign("extensions-layout", extensionLayout);

        if(signs.length < 6)
            return;

        List<Id> supportedPointFormats = Serializer.deserializeList(signs[5].trim());
        addSign("supported-point-formats", supportedPointFormats);

        if(signs.length < 7)
            return;

        List<Id> supportedCurves = Serializer.deserializeList(signs[6].trim());
        addSign("supported-curves", supportedCurves);
    }
}
