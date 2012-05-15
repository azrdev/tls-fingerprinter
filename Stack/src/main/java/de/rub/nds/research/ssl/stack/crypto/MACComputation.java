package de.rub.nds.research.ssl.stack.crypto;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * MAC computation of the record payloads.
 *
 * @author Eugen Weiss
 *
 * Mar 22, 2012
 */
public class MACComputation extends ARecordFrame {

    /**Message authentication code.*/
    private Mac mac = null;
    /**Sequence number.*/
    private byte[] seqNum = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    /**
     * Initialize MAC with its properties.
     * @param key Secret key
     * @param macName Name of MAC algorithm
     */
    public MACComputation(final SecretKey key, final String macName) {
        try {
            mac = Mac.getInstance("Hmac" + macName);
            mac.init(key);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
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
        /*concatenate sequence number, content type,
        protocol version, length and payload*/
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


        //compute the MAC of the message
        return mac.doFinal(data);
    }

}
