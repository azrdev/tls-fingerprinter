package de.rub.nds.ssl.stack.workflows.commons;

import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.SecurityParameters;
import de.rub.nds.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

/**
 * Utility methods for message building.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Mar 15, 2012
 */
public class MessageUtils {

    /**
     * Length of the padding string.
     */
    private int paddingLength;
    /**
     * The separate byte between padding and data in a PKCS#1 message.
     */
    private byte[] separateByte = new byte[]{0x00};
    /**
     * First two bytes of a PKCS#1 message which defines the operation mode.
     */
    private byte[] mode = new byte[]{0x00, 0x02};
    /**
     * Padding string.
     */
    private byte[] padding;
    /**
     * Record header length.
     */
    private static final int HEADER_LENGTH = 5;
    /**
     * Cpunt of cipher suites.
     */
    private static final int CIPHER_SUITE_COUNT = ECipherSuite.values().length;

    /**
     * Empty constructor.
     */
    public MessageUtils() {
    }

    /**
     * Fetch the response bytes from the Input stream.
     *
     * @param in Input stream
     * @return The response bytes
     */
    public final byte[] fetchResponse(final InputStream in) {
        byte[] header = new byte[HEADER_LENGTH];
        int readBytes = 0;
        try {
            // TODO: soll so nicht sein, read darf auch mal weniger als
            // header.length zurueck liefern. Rueckgabewert muss geprueft werden.
            // Und falls das weniger war, muss hier noch mal gelesen werden, mit
            // entsprechender beruecksichtigung von timeouts.
            // TODO: readBytes nutzen!
            readBytes = in.read(header);
        } catch (IOException e) {
            e.printStackTrace();
        }
        //Determine the length of the frame
        int length = (header[3] & 0xff) << 8 | (header[4] & 0xff);
        byte[] answer = new byte[length + header.length];
        System.arraycopy(header, 0, answer, 0, header.length);
        // TODO: Ineffizienter geht es nicht mehr!!!
        Integer byteAsInt;
        for (int i = 0; i < length; i++) {
            try {
                byteAsInt = Integer.valueOf(in.read());
                answer[header.length + i] =
                        byteAsInt.byteValue();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return answer;
    }

    /**
     * Build a PKCS#1 conform message
     *
     * @param data The data
     * @return PKCS#1 conform message
     */
    public final byte[] buildPKCS1Msg(final byte[] data) {
        byte[] tmp;
//		byte [] padding = this.createPaddingString(paddingLength);
        int pointer = 0;
        int length = mode.length + padding.length + 1 + data.length;
        tmp = new byte[length];
        //add PKCS1 encryption mode bytes
        System.arraycopy(mode, 0, tmp, pointer, mode.length);
        pointer += mode.length;
        //add padding string
        System.arraycopy(padding, 0, tmp, pointer, padding.length);
        pointer += padding.length;
        //add the zero byte
        System.arraycopy(separateByte, 0, tmp, pointer, 1);
        pointer += 1;
        //add the data block
        System.arraycopy(data, 0, tmp, pointer, data.length);
        return tmp;
    }

    /**
     * Create a non-zero padding string
     *
     * @param length Length of the padding string
     * @return The bytes of the padding
     */
    public final byte[] createPaddingString(final int length) {
        padding = new byte[length];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(padding);
        //padding should not contain zero bytes
        for (int i = 0; i < length; i++) {
            int tmp = padding[i] | 0x01;
            Integer iTmp = tmp;
            padding[i] = iTmp.byteValue();
        }
        return padding;
    }

    /**
     * Change a byte[] on a specific position
     *
     * @param array The byte[] array to change
     * @param position The position within the arrayed
     * @param to Change byte
     * @return changed array
     */
    public final byte[] changeByteArray(final byte[] array,
            final POSITIONS position, final byte to) {
        byte[] newPadding = array.clone();
        int midPos = newPadding.length / 2;
        int lastPos = newPadding.length - 1;

        switch (position) {
            case FIRST:
                newPadding[0] = to;
                break;
            case MIDDLE:
                newPadding[midPos] = to;
                break;
            case LAST:
                newPadding[lastPos] = to;
                break;
            default:
                break;
        }

        return newPadding;
    }

    /**
     * Change a byte[] on arbitrary position
     *
     * @param array The byte[] array to change
     * @param position The position within the array
     * @param to Change byte
     * @return changed array
     */
    public final byte[] changeArbitraryPos(final byte[] array,
            int position, final byte to) {
        byte[] newPadding = array.clone();
        if (position < newPadding.length) {
            newPadding[position] = to;
        }
        return newPadding;
    }

    /**
     * Padding as described in Chapter 6.2.3.2 of RFC 2246
     *
     * @param data Data which should be padded
     * @param blockSize Block size of the cipher
     * @param changeByteArray True if padding should be changed
     * @return Padded data which is a multiple of the block size
     */
    public final byte[] addPadding(final byte[] data,
            final int blockSize, final boolean changePadding) {
        int padLength = 0;
        //determine how much padding bytes are needed
        if ((data.length % blockSize) != 0) {
            padLength = blockSize - (data.length % blockSize);
        } else {
            padLength = blockSize;
        }
        byte length;

        //set the value of the padding bytes
        if (changePadding) {
            length = (byte) (padLength);
        } else {
            length = (byte) (padLength - 1);
        }

        //create padding
        byte[] padding = new byte[padLength];
        for (int i = 0; i < padding.length; i++) {
            padding[i] = (byte) (length);
        }
        int pointer = 0;

        //add padding to the data
        byte[] paddedData = new byte[data.length + padLength];
        System.arraycopy(data, 0, paddedData, pointer, data.length);
        pointer += data.length;
        System.arraycopy(padding, 0, paddedData, pointer, padLength);
        return paddedData;
    }

    /**
     * Send a handshake record
     *
     * @param record The handshake record
     * @param out The output stream
     */
    public final void sendHandshakeMessage(final AHandshakeRecord record,
            final OutputStream out) {
        byte[] msg = record.encode(true);
        try {
            out.write(msg);
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Send a SSL message
     *
     * @param out Output stream
     * @param msg SSL message
     */
    public final void sendMessage(final OutputStream out, final byte[] msg)
            throws IOException {
        out.write(msg);
        // does nothing, but to be accurate
        out.flush();
    }

    /**
     * Set the client random parameter of the security parameters
     *
     * @param clientHello The client hello handshake record
     * @param param Security parameters
     */
    public final void setClientRandom(final ClientHello clientHello) {
        SecurityParameters param = SecurityParameters.getInstance();
        byte[] clientTime = clientHello.getRandom().getUnixTimestamp();
        byte[] clientValue = clientHello.getRandom().getValue();
        byte[] clientRandom =
                new byte[clientTime.length + clientValue.length];
        int pointer = 0;
        //copy the client random to the array
        System.arraycopy(clientTime, 0, clientRandom,
                pointer, clientTime.length);
        pointer += clientTime.length;
        System.arraycopy(clientValue, 0, clientRandom,
                pointer, clientValue.length);

        param.setClientRandom(clientRandom);
    }

    /**
     * Choose a batch of cipher suites using a specific pattern
     *
     * @param patterns The pattern
     * @return Batch of cipher suites
     */
    public final ECipherSuite[] constructSuiteBatch(final String[] patterns) {
        ECipherSuite[] suites = new ECipherSuite[CIPHER_SUITE_COUNT];
        int j = 0;
        for (String pattern : patterns) {
            for (ECipherSuite cipher : ECipherSuite.values()) {
                if (cipher.toString().startsWith(pattern)) {
                    suites[j] = cipher;
                    j++;
                }
            }
        }
        ECipherSuite[] tmp = new ECipherSuite[j];
        System.arraycopy(suites, 0, tmp, 0, j);
        return tmp;
    }

    /**
     * Set the length of the padding string
     *
     * @param paddingLength Length of the padding string
     */
    public final void setPaddingLength(final int paddingLength) {
        this.paddingLength = paddingLength;
    }

    /**
     * Get the length of the padding string
     *
     * @return Length of the padding string
     */
    public final int getPaddingLength() {
        return paddingLength;
    }

    /**
     * Set the separate byte between padding and data in a PKCS#1 message.
     *
     * @param separateByte The separate byte
     */
    public final void setSeparateByte(byte[] separateByte) {
        if (separateByte == null) {
            throw new IllegalArgumentException(
                    "Separate byte must not be null!");
        }
        this.separateByte = separateByte;
    }

    /**
     * Get the separate byte between padding and data in a PKCS#1 message.
     *
     * @return The separate byte
     */
    public final byte[] getSeparateByte() {
        return separateByte.clone();
    }

    /**
     * Set the first two bytes of a PKCS#1 message which stands for the
     * operation mode.
     *
     * @param mode Operation mode
     */
    public final void setMode(final byte[] mode) {
        if (mode == null) {
            throw new IllegalArgumentException(
                    "Mode bytes must not be null!");
        }
        this.mode = mode;
    }

    /**
     * Set the padding string of a PKCS#1 message.
     *
     * @param newPadding Padding string
     */
    public final void setPadding(final byte[] newPadding) {
        if (newPadding == null) {
            throw new IllegalArgumentException(
                    "Padding bytes must not be null!");
        }
        this.padding = newPadding.clone();
    }

    /**
     * Get the first two bytes of a PKCS#1 message which stands for the
     * operation mode.
     *
     * @return Operation mode
     */
    public final byte[] getMode() {
        return mode;
    }

    /**
     * Placeholder for fixed Positions, for example in a padding String, etc.
     */
    public enum POSITIONS {

        FIRST, MIDDLE, LAST
    };
}
