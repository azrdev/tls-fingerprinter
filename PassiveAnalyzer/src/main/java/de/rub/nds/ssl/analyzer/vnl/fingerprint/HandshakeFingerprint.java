package de.rub.nds.ssl.analyzer.vnl.fingerprint;

import com.google.common.base.Joiner;
import de.rub.nds.ssl.analyzer.vnl.MessageContainer;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization.Serializer;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.protocols.alert.datatypes.EAlertDescription;
import de.rub.nds.ssl.stack.protocols.commons.Id;
import de.rub.nds.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ServerHello;
import de.rub.nds.virtualnetworklayer.connection.pcap.ReassembledPacket;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import org.apache.log4j.Logger;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 * A fingerprint over the whole handshake, i.e. about order & presence of certain
 * messages (alerts, optional handshake messages etc)
 *
 * @author jBiegert azrdev@qrdn.de
 */
//TODO: also get direction of handshake msgs (e.g. for ChangeCipherSpec not obvious)
public class HandshakeFingerprint extends Fingerprint {
    private static Logger logger = Logger.getLogger(HandshakeFingerprint.class);

    /**
     * Represents type of a TLS message: EContentType and (if present)
     * content-dependent subtype
     */
    public interface MessageTypes {
        public abstract String serialize();
    }

    public static class MessageType implements MessageTypes {
        public final Id contentType;
        public MessageType(Id contentType) {
            this.contentType = contentType;
        }
        @Override
        public String serialize() {
            return Serializer.serializeSign(contentType);
        }
        @Override
        public String toString() {
            return String.valueOf(contentType);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            MessageType that = (MessageType) o;

            if (contentType != null ?
                    !contentType.equals(that.contentType) :
                    that.contentType != null)
                return false;

            return true;
        }

        @Override
        public int hashCode() {
            return contentType != null ? contentType.hashCode() : 0;
        }
    }

    public static class MessageTypeSubtype extends MessageType implements MessageTypes {
        public final Id subType;
        public MessageTypeSubtype(Id contentType, Id subType) {
            super(contentType);
            this.subType = subType;
        }
        @Override
        public String toString() {
            return contentType + "-" + subType;
        }
        @Override
        public String serialize() {
            return super.serialize() + "-" + Serializer.serializeSign(subType);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            if (!super.equals(o)) return false;

            MessageTypeSubtype that = (MessageTypeSubtype) o;

            if (subType != null ? !subType.equals(that.subType) : that.subType != null)
                return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = super.hashCode();
            result = 31 * result + (subType != null ? subType.hashCode() : 0);
            return result;
        }
    }

    /**
     * Cloning ctor: create a copy of original
     */
    public HandshakeFingerprint(HandshakeFingerprint original) {
        super(original);
    }

    public HandshakeFingerprint(String serialized) {
        deserialize(serialized);
    }

    public HandshakeFingerprint(List<MessageContainer> frameList) {
        // sign: message-types

        final List<MessageTypes> messageTypes = new LinkedList<>();
        for (MessageContainer messageContainer : frameList) {
            final ARecordFrame record = messageContainer.getCurrentRecord();

            final Id contentType;
            try {
                contentType = new Id(record.getContentType().getId());
            } catch(NullPointerException e) {
                messageTypes.add(new MessageType(null));
                continue;
            }

            try {
                switch (record.getContentType()) {
                    case ALERT:
                        final EAlertDescription alertDesc =
                                ((Alert) record).getAlertDescription();
                        messageTypes.add(new MessageTypeSubtype(contentType,
                                new Id(alertDesc.getId())));
                        break;
                    case HANDSHAKE:
                        final AHandshakeRecord handshakeRecord = (AHandshakeRecord) record;
                        messageTypes.add(new MessageTypeSubtype(contentType,
                                new Id(handshakeRecord.getMessageType().getId())));
                        break;

                    // subtype (request / response field) not implemented
                    case HEARTBEAT:
                        // the following types don't have subtypes
                    case APPLICATION:
                    case CHANGE_CIPHER_SPEC:
                        messageTypes.add(new MessageType(contentType));
                        break;

                    default:
                        messageTypes.add(new MessageType(null));
                }
            } catch(IllegalArgumentException|NullPointerException e) {
                logger.debug("Error getting message subType: " + e);
                // error getting subtype -> add it, at least
                messageTypes.add(new MessageTypeSubtype(contentType, null));
            }
        }
        addSign("message-types", messageTypes);

        // sign: session-ids-match

        byte[] clientSessionId = null;
        byte[] serverSessionId = null;

        for(MessageContainer mc : frameList) {
            if(mc.getCurrentRecord() == null)
                continue;

            ARecordFrame currentRecord = mc.getCurrentRecord();
            if(currentRecord instanceof ClientHello) {
                try {
                    clientSessionId = ((ClientHello) currentRecord).getSessionID().getId();
                } catch(NullPointerException e) {
                    break;
                }
            }
            if(currentRecord instanceof ServerHello) {
                try {
                    serverSessionId = ((ServerHello) currentRecord).getSessionID().getId();
                } catch(NullPointerException e) {
                    break;
                }
            }

            if(clientSessionId != null && serverSessionId != null) {
                addSign("session-ids-match",
                        Arrays.equals(clientSessionId, serverSessionId));
                break;
            }
        }

        // sign: ssl-fragment-layout
        // sign: tcp-fragment-layout

        final List<String> sslFragmentLayout = new LinkedList<>();
        final List<String> tcpSegmentLayout = new LinkedList<>();

        for (MessageContainer messageContainer : frameList) {
            final Joiner j = Joiner.on("-");
            sslFragmentLayout.add(j.join(messageContainer.getFragmentSourceRecords()));
            tcpSegmentLayout.add(j.join(messageContainer.getRecordSourceSegments()));
        }
        addSign("ssl-fragment-layout", sslFragmentLayout);
        addSign("tcp-segment-layout", tcpSegmentLayout);
    }

    @Override
    public List<String> serializationSigns() {
        return Arrays.asList(
                "message-types",
                "session-ids-match",
                "ssl-fragment-layout",
                "tcp-segment-layout");
    }

    @Override
    public void deserialize(String serialized) {
        String[] signs = serialized.trim().split(SERIALIZATION_DELIMITER, -1);
        if(signs.length < 1)
            throw new IllegalArgumentException("Serialized form of fingerprint invalid: "
                + "Wrong sign count " + signs.length);

        List<MessageTypes> messageTypes = new LinkedList<>();
        for(String mt : Serializer.deserializeStringList(signs[0])) {
            messageTypes.add(Serializer.deserializeMessageTypes(mt));
        }
        addSign("message-types", messageTypes);

        if(signs.length < 2)
            return;
        addSign("session-ids-match", Serializer.deserializeBoolean(signs[1]));

        if(signs.length < 3)
            return;
        addSign("ssl-fragment-layout", Serializer.deserializeStringList(signs[2]));

        if(signs.length < 4)
            return;
        addSign("tcp-segment-layout", Serializer.deserializeStringList(signs[3]));
    }
}
