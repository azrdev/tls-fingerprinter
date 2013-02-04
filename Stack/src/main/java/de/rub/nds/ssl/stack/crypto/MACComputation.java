package de.rub.nds.ssl.stack.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.apache.log4j.Logger;

/**
 * MAC computation of the record payloads.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 *
 * Mar 22, 2012
 */
public class MACComputation {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();
    /**
     * Message authentication code.
     */
    private Mac mac = null;
    /**
     * Sequence number.
     */
    private byte[] seqNum = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    /**
     * Max value of a single byte.
     */
    private static final int BYTE_MAX = 255;

    /**
     * Initialize MAC with its properties.
     *
     * @param key Secret key
     * @param macName Name of MAC algorithm
     */
    public MACComputation(final SecretKey key, final String macName) {
        try {
            mac = Mac.getInstance("Hmac" + macName);
            mac.init(key);
        } catch (NoSuchAlgorithmException e) {
            logger.error("HMAC not available.", e);
        
        } catch (InvalidKeyException e) {
            logger.error("Invalid key.", e);
        }
    }

    /**
     * Compute MAC as described in Chapter 6.2.3.1 in RFC 2246.
     *
     * @param protocolVersion Protocol version
     * @param contentType Content type of the message
     * @param payloadLength Length of message payload
     * @param payload Payload of the message
     * @return MAC value
     */
    public final byte[] computeMAC(final byte[] protocolVersion,
            final byte contentType, final byte[] payloadLength,
            final byte[] payload) {
        /*
         * concatenate sequence number, content type, protocol version, length
         * and payload
         */
        byte[] data = new byte[seqNum.length + 1
                + protocolVersion.length
                + payloadLength.length + payload.length];
        int pointer = 0;

        //add sequence number
        System.arraycopy(seqNum, 0, data, pointer, seqNum.length);
        pointer += seqNum.length;

        //add content type
        data[pointer] = contentType;
        pointer += 1;

        //add protocol version
        System.arraycopy(protocolVersion, 0, data, pointer,
                protocolVersion.length);
        pointer += protocolVersion.length;

        //add length bytes
        System.arraycopy(payloadLength, 0, data, pointer, payloadLength.length);
        pointer += payloadLength.length;

        //add record payload
        System.arraycopy(payload, 0, data, pointer, payload.length);

        //increment the sequence number
        this.incrementArray(seqNum);

        //compute the MAC of the message
        return mac.doFinal(data);
    }

    /**
     * Increment a byte array by one.
     *
     * @param seq Byte array to increment
     * @return Incremented byte array
     */
    public final byte[] incrementArray(final byte[] seq) {
        for (int i = seq.length - 1; i >= 0; i--) {
            Byte valueByte = seq[i];
            Integer num = valueByte.intValue();
            if (Integer.signum(num) == -1) {
                num += BYTE_MAX + 1;
            }
            if (num < BYTE_MAX) {
                num++;
                seq[i] = num.byteValue();
                break;
            } else if (i == 0) {
                /*
                 * reset array and start by 0 if maximum number is reached
                 */
                for (int j = 0; j < seq.length; j++) {
                    seq[j] = 0x00;
                }
            }
        }
        return seq;
    }
}
