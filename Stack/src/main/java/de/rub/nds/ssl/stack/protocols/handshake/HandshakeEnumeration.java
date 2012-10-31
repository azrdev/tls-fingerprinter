package de.rub.nds.ssl.stack.protocols.handshake;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;

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

    /**
     * Predefined size of the messages list
     */
    final private static int DEFAULT_LIST_SIZE = 3;
    final private List<AHandshakeRecord> messages =
            new ArrayList<AHandshakeRecord>(DEFAULT_LIST_SIZE);

    
    private EKeyExchangeAlgorithm keyEKeyExchangeAlgorithm = null;
    /**
     * Slicer/Combiner for multiple handshake messages
     *
     * @param message (Multiple) handshake messages in encoded form
     * @param chained Decode single or chained with underlying frames
     */
    public HandshakeEnumeration(final byte[] message, final boolean chained, EKeyExchangeAlgorithm keyExchangeAlgorithm) {
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
    public void decode(final byte[] message, final boolean chained) {
        byte[] payloadCopy;
        byte[] tmpMessage;
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
        EProtocolVersion version = this.getProtocolVersion();

        // invoke decode
        Class<AHandshakeRecord> implClass = type.getImplementingClass();
        if (implClass == null) {
            throw new NullPointerException("implClass == NULL: type was "
                    + type);
        }

		try {

			// Can we decide this in another way?
			if ((implClass.equals(ServerKeyExchange.class) || (implClass
					.equals(ClientKeyExchange.class)))) {
				Class[] parameter = new Class[3];
				parameter[0] = byte[].class;
				parameter[1] = EKeyExchangeAlgorithm.class;
				parameter[2] = boolean.class;
				Constructor<AHandshakeRecord> constructor = implClass
						.getConstructor(parameter);
				result = constructor.newInstance(message, keyEKeyExchangeAlgorithm, false);
				result.setMessageType(type);

				// set protocol version
				Method setProtocolVersion = ARecordFrame.class
						.getDeclaredMethod("setProtocolVersion",
								EProtocolVersion.class);
				setProtocolVersion.setAccessible(true);
				setProtocolVersion.invoke(result, version);

			} else {
				Class[] parameter = new Class[2];
				parameter[0] = byte[].class;
				parameter[1] = boolean.class;
				Constructor<AHandshakeRecord> constructor = implClass
						.getConstructor(parameter);
				result = constructor.newInstance(message, false);
				result.setMessageType(type);

				// set protocol version
				Method setProtocolVersion = ARecordFrame.class
						.getDeclaredMethod("setProtocolVersion",
								EProtocolVersion.class);
				setProtocolVersion.setAccessible(true);
				setProtocolVersion.invoke(result, version);

				return result;
			}
		} catch (InstantiationException ex) {
			ex.printStackTrace();
		} catch (IllegalAccessException ex) {
			ex.printStackTrace();
		} catch (InvocationTargetException ex) {
			System.err.println("failed to invoke method for class "
					+ implClass.getCanonicalName());
			ex.printStackTrace();
		} catch (NoSuchMethodException ex) {
			System.err.println("Could not find a suiteable method for type "
					+ type + " and class " + implClass.getCanonicalName());
			ex.printStackTrace();
		}
		return null;

    }

    public AHandshakeRecord[] getMessages() {
        return messages.toArray(new AHandshakeRecord[messages.size()]);
    }
}
