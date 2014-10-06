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
import de.rub.nds.ssl.stack.protocols.handshake.extensions.EllipticCurves;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.SupportedPointFormats;
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

        Extensions extensions = serverHello.getExtensions();

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
        return Arrays.asList(
                "version",
                "cipher-suite",
                "compression-method",
                "session-id-empty",
                "extensions-layout",
                "supported-point-formats",
                "supported-curves"
        );
    }

    @Override
    public void deserialize(String serialized) {
        String[] signs = serialized.split(SERIALIZATION_DELIMITER, -1);
        if(signs.length < 5) {
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

        addSign("session-id-empty", Serializer.deserializeBoolean(signs[3]));

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
