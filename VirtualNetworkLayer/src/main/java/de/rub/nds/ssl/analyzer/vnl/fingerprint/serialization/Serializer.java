package de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization;

import de.rub.nds.ssl.analyzer.vnl.SessionIdentifier;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.Fingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;
import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.ECompressionMethod;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.Id;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import org.apache.log4j.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.*;

/**
 * Utility to serialize {@link Fingerprint}s.
 *
 * Add all types that may be signs and their serialization type to <code>serializeSign()</code>
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class Serializer {
    private static Logger logger = Logger.getLogger(Serializer.class);

    /**
     * Build the Serialized form of a sign
     */
    public static String serializeSign(Object sign) {
        if(sign == null)
            return "";

        //FIXME: better mapping & dispatch of sign-type -> serialization method. Maybe use Visitor for TLSFingerprint.serialize()

        if(sign instanceof Object[])
            return serializeList((Object[]) sign);
        else if(sign instanceof byte[]) {
            logger.debug("Serializing byte[]");
            return Utility.bytesToHex((byte[]) sign, false);
        } else if(sign instanceof Collection)
            return serializeList((Collection) sign);

        else if(sign instanceof Id)
            return Utility.bytesToHex(((Id) sign).getBytes(), false);
        else if(sign instanceof EProtocolVersion)
            return Utility.bytesToHex(((EProtocolVersion) sign).getId(), false);
        else if(sign instanceof ECompressionMethod)
            return Utility.bytesToHex(((ECompressionMethod) sign).getId(), false);
        else if(sign instanceof ECipherSuite)
            return Utility.bytesToHex(((ECipherSuite) sign).getId(), false);
        else if(sign instanceof EExtensionType)
            return Utility.bytesToHex(((EExtensionType) sign).getId(), false);
        else
            return sign.toString();
    }

    public static final String LIST_DELIMITER = ",";

    private static String serializeList(Collection arr) {
        StringBuilder sb = new StringBuilder();

        for(Object o : arr) {
            // recursive call to serialize that element
            // never put Object[] as sign value, or this will break!
            sb.append(serializeSign(o)).append(LIST_DELIMITER);
        }
        if(sb.length() > 0)
            // delete trailing delimiter
            sb.setLength(sb.length() - LIST_DELIMITER.length());

        return sb.toString();
    }

    private static String serializeList(Object[] arr) {
        return serializeList(Arrays.asList(arr));
    }

    public static List<Id> deserializeList(String serialized) {
        List<Id> bytes = new ArrayList<>(serialized.length());
        for(String item : serialized.split(LIST_DELIMITER, -1)) {
            bytes.add(new Id(Utility.hexToBytes(item.trim())));
        }

        return bytes;
    }

    public static String serialize(SessionIdentifier session,
                                   TLSFingerprint tlsFingerprint) {
        return session.serialize() + "\n" + tlsFingerprint.serialize();
    }

    public static Map<SessionIdentifier, List<TLSFingerprint>> deserialize(
            BufferedReader reader) throws IOException {
        Map<SessionIdentifier, List<TLSFingerprint>> fingerprints = new HashMap<>();

        String line;
        SessionIdentifier sidBuffer = null;
        StringBuilder fpBuffer = new StringBuilder();
        while((line = reader.readLine()) != null) {

            if(line.startsWith("#"))
                continue;
            if(line.isEmpty())
                continue;

            if(line.startsWith("\t")) {
                fpBuffer.append(line).append('\n');
            } else {
                commitFingerprint(sidBuffer, fpBuffer, fingerprints);

                try {
                    sidBuffer = new SessionIdentifier(line);
                } catch(IllegalArgumentException e) {
                    logger.debug("Error reading SessionIdentifier: " + e, e);
                    sidBuffer = null;
                }
            }
        }

        commitFingerprint(sidBuffer, fpBuffer, fingerprints);

        return fingerprints;
    }

    private static void commitFingerprint(SessionIdentifier sidBuffer,
                  StringBuilder fpBuffer,
                  Map<SessionIdentifier, List<TLSFingerprint>> fingerprints) {
        TLSFingerprint fp = null;
        try {
            fp = new TLSFingerprint(fpBuffer.toString());
        } catch(IllegalArgumentException e) {
            logger.debug("Error reading fingerprint: " + e, e);
        }
        fpBuffer.setLength(0);

        if(sidBuffer != null && fp != null) {
            List<TLSFingerprint> fps;
            if(fingerprints.containsKey(sidBuffer)) {
                // append to list of fingerprints belonging to SessionIdentifier
                fps = fingerprints.get(sidBuffer);
                if(! fps.contains(fp)) {
                    fps.add(fp);
                } else {
                    logger.warn("Duplicate fingerprint in file for " + sidBuffer);
                }
            } else {
                fps = new ArrayList<>(1);
                fps.add(fp);
                fingerprints.put(sidBuffer, fps);
            }
        }
    }
}
