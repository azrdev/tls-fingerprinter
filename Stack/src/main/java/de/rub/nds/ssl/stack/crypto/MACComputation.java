package de.rub.nds.ssl.stack.crypto;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.apache.log4j.Logger;

/**
 * MAC computation of the record payloads.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @author Oliver Domke - oliver.domke@ruhr-uni-bochum.de
 * @version 0.2
 *
 * Feb 05, 2014
 */
public class MACComputation {

    /**
     * Log4j logger initialization.
     */
    private static final Logger logger = Logger.getRootLogger();
    /**
     * Message authentication code.
     */
    private Mac mac = null;
    /**
     * Sequence number.
     */
    private long seqNum = 0;
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
    public final byte[] computeMAC(final byte[] protocolVersion, final byte contentType, final byte[] payloadLength, final byte[] payload) {
        /*
         * concatenate sequence number, content type, protocol version, length
         * and payload
         */
        byte[] data = new byte[8 + 1
                + protocolVersion.length
                + payloadLength.length + payload.length];
        int pointer = 0;

        //add sequence number
        System.arraycopy(getSequenceNumber(), 0, data, pointer, 8);
        pointer += 8;

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
        seqNum++;

        //compute the MAC of the message
        return mac.doFinal(data);
    }
    
    private byte[] getSequenceNumber(){
        return ByteBuffer.allocate(8).putLong(seqNum).array();
    }

    public void decreaseSequenceNumber(){
        seqNum--;
    }
    
}