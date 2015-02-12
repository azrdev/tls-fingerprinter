package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import com.google.common.base.Joiner;
import de.rub.nds.ssl.analyzer.vnl.Connection;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.Serializer;
import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.Id;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.Extensions;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.EllipticCurves;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.RenegotiationInfo;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.SupportedPointFormats;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import de.rub.nds.virtualnetworklayer.util.Util;
import org.apache.log4j.Logger;

import java.util.Arrays;
import java.util.List;

public class ClientHelloFingerprint extends Fingerprint<ClientHelloFingerprint> {
    private static Logger logger = Logger.getLogger(ClientHelloFingerprint.class);

    public static ClientHelloFingerprint create(ClientHello clientHello) {
        return new ClientHelloFingerprint(clientHello);
    }

    public static ClientHelloFingerprint create(Connection connection) {
        return new ClientHelloFingerprint(connection.getClientHello());
    }

    public static ClientHelloFingerprint copy(ClientHelloFingerprint original) {
        return new ClientHelloFingerprint(original);
    }

    @Deprecated
    public static ClientHelloFingerprint deserializeFingerprint(String serialized) {
        return new ClientHelloFingerprint().deserialize(serialized);
    }

    public static ClientHelloFingerprint deserializeFingerprint(List<String> signs) {
        return new ClientHelloFingerprint().deserialize(signs);
    }


    private ClientHelloFingerprint() {
        super();
    }

    private ClientHelloFingerprint(ClientHelloFingerprint original) {
        super(original);
    }

    private ClientHelloFingerprint(ClientHello clientHello) {
        if(clientHello == null)
            throw new NotMatchingException();

        addSign("version", clientHello.getProtocolVersion());

        //TODO: make fuzzy
        addSign("compression-method-list",
                clientHello.getCompressionMethod().getRawMethods());
        addSign("cipher-suite-list",
                clientHello.getCipherSuites().getRawSuites());

        //TODO: remove extensions from fp?

        Extensions extensions = clientHello.getExtensions();
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
        return Arrays.asList("version",
                "compression-method-list",
                "cipher-suite-list",
                "extensions-layout",
                "supported-point-formats",
                "supported-curves",
                "renegotiation-info-length");
    }

    public ClientHelloFingerprint deserialize(final List<String> signs)
            throws IllegalArgumentException {
        if(signs.size() < 5) {
            throw new IllegalArgumentException("Serialized form of fingerprint invalid: "
                    + "Wrong sign count " + signs.size());
        }

        byte[] bytes;
        bytes = Utility.hexToBytes(signs.get(0).trim());
        addSign("version", EProtocolVersion.getProtocolVersion(bytes));

        List<Id> compressionMethods = Serializer.deserializeList(signs.get(1).trim());
        addSign("compression-method-list", compressionMethods);

        List<Id> cipherSuites = Serializer.deserializeList(signs.get(2).trim());
        addSign("cipher-suite-list", cipherSuites);

        List<Id> extensionLayout = Serializer.deserializeList(signs.get(3).trim());
        if(extensionLayout != null)
            addSign("extensions-layout", extensionLayout);

        if(signs.size() >= 5) {
            List<Id> supportedPointFormats = Serializer.deserializeList(signs.get(4).trim());
            if (supportedPointFormats != null)
                addSign("supported-point-formats", supportedPointFormats);
        }

        if(signs.size() >= 6) {
            List<Id> supportedCurves = Serializer.deserializeList(signs.get(5).trim());
            if (supportedCurves != null)
                addSign("supported-curves", supportedCurves);
        }

        if(signs.size() >= 7) {
            try {
                final String sign = signs.get(6).trim();
                if (!sign.isEmpty())
                    addSign("renegotiation-info-length",
                            Util.readBoundedInteger(sign, 0, 255));
            } catch (NumberFormatException e) {
                // probably empty
                logger.debug("Cannot parse renegotiation-info-length. signature: " +
                        Joiner.on(':').join(signs));
            }
        }
        return this;
    }
}
