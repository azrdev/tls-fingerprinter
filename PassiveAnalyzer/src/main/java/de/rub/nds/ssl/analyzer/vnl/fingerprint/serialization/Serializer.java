package de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;
import de.rub.nds.ssl.analyzer.vnl.SessionIdentifier;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.*;
import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.ECompressionMethod;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.Id;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECPointFormat;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ENamedCurve;
import de.rub.nds.virtualnetworklayer.p0f.Module;
import de.rub.nds.virtualnetworklayer.p0f.signature.MTUSignature;
import de.rub.nds.virtualnetworklayer.p0f.signature.TCPSignature;
import org.apache.log4j.Logger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.BufferedReader;
import java.io.IOException;
import java.lang.IllegalArgumentException;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Utility to serialize {@link Fingerprint}s.
 *
 * Add all types that may be signs and their serialization type to <code>serializeSign()</code>
 * <br>
 * TODO: rework this with an architecture
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class Serializer {
    private static Logger logger = Logger.getLogger(Serializer.class);

    /**
     * Build the Serialized form of a sign.
     * <br>
     * <b>NOTE</b>: never put Object[] as sign value, or things will break!
     */
    public static String serializeSign(@Nullable Object sign) {
        if(sign == null)
            return "";

        //FIXME: better mapping & dispatch of sign-type -> serialization method. Maybe use Visitor for TLSFingerprint.serialize()

        if(sign instanceof Object[])
            return serializeList((Object[]) sign);
        else if(sign instanceof byte[]) {
            logger.warn("Serializing byte[]");
            return Utility.bytesToHex((byte[]) sign, false);
        } else if(sign instanceof Collection)
            return serializeList((Collection) sign);

        else if(sign instanceof Id)
            return Utility.bytesToHex(((Id) sign).getBytes(), false);
        else if(sign instanceof HandshakeFingerprint.MessageTypes) {
            return ((HandshakeFingerprint.MessageTypes) sign).serialize();
        } else if(sign instanceof EProtocolVersion)
            return Utility.bytesToHex(((EProtocolVersion) sign).getId(), false);
        else if(sign instanceof ECompressionMethod)
            return Utility.bytesToHex(((ECompressionMethod) sign).getId(), false);
        else if(sign instanceof ECipherSuite)
            return Utility.bytesToHex(((ECipherSuite) sign).getId(), false);
        else if(sign instanceof EExtensionType)
            return Utility.bytesToHex(((EExtensionType) sign).getId(), false);
        else if(sign instanceof ENamedCurve)
            return Utility.bytesToHex(((ENamedCurve) sign).getId(), false);
        else if(sign instanceof EECPointFormat)
            return Utility.bytesToHex(((EECPointFormat) sign).getId(), false);
        else
            return sign.toString();
    }

    public static final String LIST_DELIMITER = ",";

    private static String serializeList(@Nonnull Collection collection) {
        if(collection.isEmpty())
            return LIST_DELIMITER;

        StringBuilder sb = new StringBuilder();

        for(Object o : collection) {
            // recursive call to serialize that element
            // never put Object[] as sign value, or this will break!
            sb.append(serializeSign(o)).append(LIST_DELIMITER);
        }
        if(sb.length() > 0)
            // delete trailing delimiter
            sb.setLength(sb.length() - LIST_DELIMITER.length());

        return sb.toString();
    }

    private static String serializeList(@Nonnull Object[] arr) {
        return serializeList(Arrays.asList(arr));
    }

    public static String serialize(SessionIdentifier session,
                                   TLSFingerprint tlsFingerprint) {
        return session.serialize() + tlsFingerprint.serialize();
    }

    public static String serialize(@Nonnull TLSFingerprint fp) {
        return serializeHandshake(fp.getHandshakeSignature())
                + serializeServerHello(fp.getServerHelloSignature())
                + serializeServerTcp(fp.getServerTcpSignature())
                + serializeServerMtu(fp.getServerMtuSignature());
    }

    public static String serializeHandshake(@Nullable Fingerprint handshakeSignature) {
        if(handshakeSignature == null)
            return "";

        return String.format("\t%s: %s\n", FingerprintId.Handshake.id,
                handshakeSignature.serialize());
    }

    public static String serializeClientHello(@Nullable Fingerprint clientHelloSignature) {
        if(clientHelloSignature == null) {
            return "";
        }

        return String.format("\t%s: %s\n", FingerprintId.ClientHello.id,
                clientHelloSignature.serialize());
    }

    public static String serializeServerHello(@Nullable Fingerprint serverHelloSignature) {
        if(serverHelloSignature == null) {
            return "";
        }

        return String.format("\t%s: %s\n", FingerprintId.ServerHello.id,
                serverHelloSignature.serialize());
    }

    public static String serializeServerTcp(@Nullable
            de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint.Signature sig) {
        if(sig == null)
            return "";

        return String.format("\t%s: %s\n", FingerprintId.ServerTcp.id,
                TCPSignature.writeToString(sig));
    }

    public static String serializeServerMtu(@Nullable
            de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint.Signature sig) {
        if(sig == null)
            return "";

        return String.format("\t%s: %s\n", FingerprintId.ServerMtu.id,
                MTUSignature.writeToString(sig));
    }

    public static HandshakeFingerprint.MessageTypes
    deserializeMessageTypes(@Nonnull String serialized) {
        final String[] types = serialized.split("-", 2);
        final Id contentType = new Id(Utility.hexToBytes(types[0]));
        if(types.length > 1) {
            final byte[] subType = Utility.hexToBytes(types[1]);
            if(subType != null && subType.length > 0)
                return new HandshakeFingerprint.MessageTypeSubtype(contentType,
                        new Id(subType));
            else
                return new HandshakeFingerprint.MessageTypeSubtype(contentType, null);
        } else
            return new HandshakeFingerprint.MessageType(contentType);
    }

    public static Boolean deserializeBoolean(@Nonnull String serialized)
            throws SerializationException {
        final String trimmed = serialized.trim().toLowerCase();
        if(trimmed.equals("true"))
            return true;
        if(trimmed.equals("false"))
            return false;
        throw new SerializationException("No boolean value: " + trimmed);
    }

    /**
     * Parse serialized list of Id instances
     * @return null if serialized was empty, else a list of Ids without nulls
     * @throws IllegalArgumentException If there is an unparseable char in any Id
     */
    public static List<Id> deserializeList(@Nonnull String serialized) {
        if(serialized.isEmpty())
            return null; //TODO: return empty list  / throw
        List<Id> bytes = new ArrayList<>(serialized.length());
        for(String item : serialized.split(LIST_DELIMITER, -1)) {
            if(item.isEmpty())
                continue;
            bytes.add(new Id(Utility.hexToBytes(item.trim())));
        }

        return bytes;
    }

    public static List<String> deserializeStringList(@Nonnull String serialized) {
        List<String> strings = new ArrayList<>(serialized.length());
        for(String item : serialized.split(LIST_DELIMITER, -1)) {
            strings.add(item.trim());
        }
        return strings;
    }

    public static SetMultimap<SessionIdentifier, TLSFingerprint>
    deserialize(@Nonnull BufferedReader reader) throws IOException {
        SetMultimap<SessionIdentifier, TLSFingerprint> fingerprints =
                HashMultimap.create();

        String line;
        SessionIdentifier sid = null;
        ClientHelloFingerprint clientHelloSignature = null;
        ServerHelloFingerprint serverHelloSignature = null;
        HandshakeFingerprint handshakeSignature = null;
        TCPSignature serverTcpSignature = null;
        MTUSignature serverMtuSignature = null;

        while((line = reader.readLine()) != null) {
            final String line_trimmed = line.trim();

            if(line_trimmed.startsWith("#"))
                continue;
            if(line_trimmed.isEmpty())
                continue;

            if(line.startsWith("\t")) {
                try {
                    String[] split = line.trim().split("\\s", 2);

                    if (FingerprintId.ClientHello.isAtStart(split[0])) {
                        clientHelloSignature = new ClientHelloFingerprint(split[1]);
                        if(sid != null) sid.setClientHelloSignature(clientHelloSignature);
                    } else if (FingerprintId.ServerHello.isAtStart(split[0])) {
                        serverHelloSignature = new ServerHelloFingerprint(split[1]);
                    } else if (FingerprintId.ServerTcp.isAtStart(split[0])) {
                        serverTcpSignature = new TCPSignature(split[1], Module.Direction.Response);
                    } else if (FingerprintId.ServerMtu.isAtStart(split[0])) {
                        serverMtuSignature = new MTUSignature(split[1]);
                    } else if (FingerprintId.Handshake.isAtStart(split[0])) {
                        handshakeSignature = new HandshakeFingerprint(split[1]);
                    } else {
                        logger.debug("Unrecognized signature: " + line);
                    }
                } catch(IllegalArgumentException ex) {
                    logger.debug("Error reading signature: " + ex + " - " + line);
                }
            } else {
                commitFingerprint(sid, new TLSFingerprint(handshakeSignature,
                        serverHelloSignature, serverTcpSignature, serverMtuSignature),
                        fingerprints);
                clientHelloSignature = null;
                serverHelloSignature = null;
                serverTcpSignature = null;
                serverMtuSignature = null;
                handshakeSignature = null;

                try {
                    sid = new SessionIdentifier(line);
                } catch(IllegalArgumentException e) {
                    logger.debug("Error reading SessionIdentifier: " + e, e);
                    sid = null;
                }
            }
        }

        commitFingerprint(sid, new TLSFingerprint(handshakeSignature,
                serverHelloSignature, serverTcpSignature, serverMtuSignature),
                fingerprints);

        return fingerprints;
    }

    /**
     * helper for {@link #deserialize(java.io.BufferedReader)}
     */
    private static void commitFingerprint(
            @Nullable SessionIdentifier sessionId,
            @Nullable TLSFingerprint tlsFingerprint,
            @Nonnull SetMultimap<SessionIdentifier, TLSFingerprint> fingerprints) {

        if(sessionId != null && tlsFingerprint != null) {
            if (fingerprints.containsEntry(sessionId, tlsFingerprint)) {
                logger.warn("Duplicate fingerprint in file for " + sessionId);
                logger.trace("fingerprint: " + tlsFingerprint);
            } else {
                fingerprints.put(sessionId, tlsFingerprint);
            }
        }
    }

    private enum FingerprintId {
        ClientHello("ClientHello"),
        ServerHello("ServerHello"),
        ServerTcp("ServerTCP"),
        ServerMtu("ServerMTU"),
        Handshake("Handshake");

        public final String id;
        private final Pattern pattern;
        FingerprintId(String id) {
            this.id = id;
            pattern = Pattern.compile(id, Pattern.LITERAL | Pattern.CASE_INSENSITIVE);
        }
        public boolean isAtStart(CharSequence input) {
            return pattern.matcher(input).lookingAt();
        }
    }
}
