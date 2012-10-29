package de.rub.nds.ssl.stack.protocols.handshake;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
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

    /**
     * Predefined size of the messages list
     */
    final private static int DEFAULT_LIST_SIZE = 3;
    final private List<AHandshakeRecord> messages =
            new ArrayList<AHandshakeRecord>(DEFAULT_LIST_SIZE);

    /**
     * Slicer/Combiner for multiple handshake messages
     *
     * @param message (Multiple) handshake messages in encoded form
     * @param chained Decode single or chained with underlying frames
     */
    public HandshakeEnumeration(final byte[] message, final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
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
    public void decode(final byte[] message, final boolean chained) {
        byte[] payloadCopy;
        byte[] tmpMessage = null;
        byte tmpMessageType;
        int tmpMessageLength;
        AHandshakeRecord tmpHandshakeMsg;
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
                throw new IllegalArgumentException("Handshake record too short. payloadCopy.length only " + payloadCopy.length + " but expected at least "  + (pointer + tmpMessageLength));
            }
            tmpMessage = new byte[tmpMessageLength];
            System.arraycopy(payloadCopy, pointer, tmpMessage, 0,
                    tmpMessage.length);
            pointer += tmpMessage.length;

            // 4. add message to message list
            tmpHandshakeMsg = delegateDecoding(tmpMessageType, tmpMessage);
            msgObserve.statusChanged(tmpHandshakeMsg);
            messages.add(tmpHandshakeMsg);
        }
    }

    /**
     * Delegates decoding process to the implementing message class
     *
     * @param messageType Message type
     * @param message Message to decode
     * @return A decoded handshake record object
     */
    private AHandshakeRecord delegateDecoding(final byte messageType,
            final byte[] message) {
        AHandshakeRecord result = null;
        EMessageType type = EMessageType.getMessageType(messageType);

        // invoke decode
        Class<AHandshakeRecord> implClass = type.getImplementingClass();
        if (implClass == null) {
        	throw new NullPointerException("implClass == NULL: type was " + type);
        }
        Class[] parameter = new Class[2];
        parameter[0] = byte[].class;
        parameter[1] = boolean.class;
        try {
            Constructor<AHandshakeRecord> constrcutor =
                    implClass.getConstructor(parameter);
            result = constrcutor.newInstance(message, false);
            result.setMessageType(type);
        } catch (InstantiationException ex) {
            // implementing class could not be instantiated
        } catch (IllegalAccessException ex) {
            // visibilty of method has changed
        } catch (InvocationTargetException ex) {
            // issues during method invocation
        } catch (NoSuchMethodException ex) {
            // no suitable implementing class found
        }

        return result;
    }

    public AHandshakeRecord[] getMessages() {
        return messages.toArray(new AHandshakeRecord[messages.size()]);
    }
}
