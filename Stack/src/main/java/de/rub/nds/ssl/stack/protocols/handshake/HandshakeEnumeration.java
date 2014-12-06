package de.rub.nds.ssl.stack.protocols.handshake;

import de.rub.nds.ssl.stack.exceptions.UnknownHandshakeMessageTypeException;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EMessageType;
import org.apache.log4j.Logger;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * Handshake Layer for multiple handshake messages
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Dec 19, 2011
 */
final public class HandshakeEnumeration extends ARecordFrame {
    private static Logger logger = Logger.getLogger(HandshakeEnumeration.class);

    private final List<AHandshakeRecord> messages = new ArrayList<>(3);

    private EKeyExchangeAlgorithm keyEKeyExchangeAlgorithm = null;

    /**
     * Slicer/Combiner for multiple handshake messages
     *
     * @param message (Multiple) handshake messages in encoded form
     * @param chained Decode single or chained with underlying frames
     * @param keyExchangeAlgorithm
     */
    public HandshakeEnumeration(final byte[] message, final boolean chained,
            EKeyExchangeAlgorithm keyExchangeAlgorithm) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();

        this.keyEKeyExchangeAlgorithm = keyExchangeAlgorithm;
        this.decode(message, chained);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encode(final boolean chained) {
        final List<byte[]> encMessages = new ArrayList<byte[]>(messages.size());
        byte[] result;

        int pointer = 0;
        byte[] tmp;
        // encode all handshake messages
        for (AHandshakeRecord record : messages) {
            tmp = record.encode(false);
            encMessages.add(tmp);
            pointer += tmp.length;
        }

        // copy together
        result = new byte[pointer];
        pointer = 0;
        for (byte[] message : encMessages) {
            System.arraycopy(message, 0, result, pointer, message.length);
            pointer += message.length;
        }

        super.setPayload(result);
        return chained ? super.encode(true) : result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        byte[] payloadCopy;
        byte[] tmpMessage;
        byte tmpMessageType;
        int tmpMessageLength;
        MessageObservable msgObserve = MessageObservable.getInstance();
        int pointer = 0;

        // clear all messages contained in the list
        messages.clear();

        if (chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }
        // payload already deep copied
        payloadCopy = getPayload();

        //comment size check because ServerHelloDone is smaller than LENGTH_MINIMUM_ENCODED
        // check size
//        if (payloadCopy.length < LENGTH_MINIMUM_ENCODED) {
//            throw new IllegalArgumentException("Handshake record too short.");
//        }

        while (payloadCopy.length >= pointer
                + AHandshakeRecord.LENGTH_MINIMUM_ENCODED) {
            //TODO: this duplicates AHandshakeRecord.decode()

            // 1. extract message type
            tmpMessageType = payloadCopy[pointer];
            pointer += EMessageType.LENGTH_ENCODED;

            // 2. determine message length
            tmpMessageLength = extractLength(payloadCopy, pointer,
                    AHandshakeRecord.LENGTH_MINIMUM_ENCODED
                    - EMessageType.LENGTH_ENCODED);
            pointer += AHandshakeRecord.LENGTH_MINIMUM_ENCODED
                    - EMessageType.LENGTH_ENCODED;

            // 3. extract message
            if (payloadCopy.length < pointer + tmpMessageLength) {
                throw new IllegalArgumentException("Handshake record too short."
                        + " payloadCopy.length only " + payloadCopy.length
                        + ", but expected at least "
                        + (pointer + tmpMessageLength));
            }
            tmpMessage = new byte[tmpMessageLength];
            System.arraycopy(payloadCopy, pointer, tmpMessage, 0,
                    tmpMessage.length);
            pointer += tmpMessage.length;

            // 4. add message to message list
            try {
                EMessageType messageType = EMessageType.getMessageType(tmpMessageType);
                AHandshakeRecord handshakeMsg = delegateDecoding(messageType, tmpMessage);
                msgObserve.statusChanged(handshakeMsg);
                messages.add(handshakeMsg);

                if(handshakeMsg.getMessageType() == EMessageType.SERVER_HELLO) {
                    ServerHello sh = (ServerHello) handshakeMsg;
                    keyEKeyExchangeAlgorithm =
                            sh.getCipherSuite().getKeyExchangeAlgorithm();
                }
            } catch (UnknownHandshakeMessageTypeException e) {
                logger.warn(e);
            } catch (IllegalArgumentException e) {
                logger.warn("cannot decode Handshake record: " + e);
            }
        }
    }

    /**
     * Delegates decoding process to the implementing message class.
     *
     * @param messageType Message type
     * @param message Message to decode
     * @return A decoded handshake record object
     */
    private AHandshakeRecord delegateDecoding(final EMessageType messageType,
            final byte[] message) {
        AHandshakeRecord result = null;
        EProtocolVersion version = this.getProtocolVersion();

        // invoke decode
        Class<AHandshakeRecord> implClass = messageType.getImplementingClass();
        if (implClass == null) {
            throw new IllegalArgumentException(
                    "No Implementation found for Handshake message type " + messageType);
        }
        
        try {
            Class[] parameter;
            Constructor<AHandshakeRecord> constructor;
            switch(messageType) {
                case SERVER_KEY_EXCHANGE:
                case CLIENT_KEY_EXCHANGE:
                    parameter = new Class[3];
                    parameter[0] = byte[].class;
                    parameter[1] = EKeyExchangeAlgorithm.class;
                    parameter[2] = boolean.class;
                    constructor = implClass.getConstructor(parameter);
                    result = constructor.newInstance(message,
                            keyEKeyExchangeAlgorithm, false);
                    break;
                default:
                    parameter = new Class[2];
                    parameter[0] = byte[].class;
                    parameter[1] = boolean.class;
                    constructor = implClass.getConstructor(parameter);
                    result = constructor.newInstance(message, false);
            }
            result.setMessageType(messageType);

            // set protocol version
            Method setProtocolVersion = ARecordFrame.class.getDeclaredMethod(
                    "setProtocolVersion", EProtocolVersion.class);
            setProtocolVersion.setAccessible(true);
            setProtocolVersion.invoke(result, version);
        } catch (InstantiationException |
                IllegalAccessException |
                NoSuchMethodException ex) {
            throw new IllegalArgumentException("could not decode handshake message " + ex);
        } catch(InvocationTargetException ex) {
            //TODO: InvocationTargetException(KeyExchangeAlgorithm null) happens with ClientKeyExchange message - debug why
            throw new IllegalArgumentException(
                    "could not decode handshake message " + ex.getCause());
        }
        return result;
    }

    public AHandshakeRecord[] getMessages() {
        return messages.toArray(new AHandshakeRecord[messages.size()]);
    }

    public List<AHandshakeRecord> getMessagesList() {
        return new ArrayList<>(messages);
    }
}
