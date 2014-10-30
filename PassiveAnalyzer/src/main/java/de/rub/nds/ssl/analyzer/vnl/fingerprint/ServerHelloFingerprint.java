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
import de.rub.nds.ssl.stack.protocols.handshake.extensions.RenegotiationInfo;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.SupportedPointFormats;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import de.rub.nds.virtualnetworklayer.util.Util;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ServerHelloFingerprint extends Fingerprint {
    private static Logger logger = Logger.getLogger(ServerHelloFingerprint.class);

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
        if(extensions == null)
            return;
        addSign("extensions-layout", extensions.getRawExtensionTypes());

        // below are handled specific extensions, if present

        SupportedPointFormats supportedPointFormats =
                extensions.getExtension(EExtensionType.EC_POINT_FORMATS);
        if(supportedPointFormats != null) {
            addSign("supported-point-formats",
                    supportedPointFormats.getRawPointFormats());
        }

        EllipticCurves supportedCurves =
                extensions.getExtension(EExtensionType.ELLIPTIC_CURVES);
        if(supportedCurves != null) {
            addSign("supported-curves", supportedCurves.getRawSupportedCurves());
        }

        RenegotiationInfo renegotiationInfo =
                extensions.getExtension(EExtensionType.RENEGOTIATION_INFO);
        if(renegotiationInfo != null) {
            addSign("renegotiation-info-length",
                    renegotiationInfo.getRenegotiatedConnection().length);
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
                "supported-curves",
                "renegotiation-info-length"
        );
    }

    @Override
    public void deserialize(String serialized) {
        String[] signs = serialized.trim().split(SERIALIZATION_DELIMITER, -1);
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
        if(extensionLayout != null)
            addSign("extensions-layout", extensionLayout);

        if(signs.length < 6)
            return;
        List<Id> supportedPointFormats = Serializer.deserializeList(signs[5].trim());
        if(supportedPointFormats != null)
            addSign("supported-point-formats", supportedPointFormats);

        if(signs.length < 7)
            return;
        List<Id> supportedCurves = Serializer.deserializeList(signs[6].trim());
        if(supportedCurves != null)
            addSign("supported-curves", supportedCurves);

        if(signs.length < 8)
            return;
        try {
            final String sign = signs[7].trim();
            if(!sign.isEmpty())
                addSign("renegotiation-info-length",
                        Util.readBoundedInteger(sign, 0, 255));
        } catch(NumberFormatException e) {
            // probably empty
            logger.debug("Cannot parse renegotiation-info-length. signature: " +
                    serialized);
        }
    }
}
