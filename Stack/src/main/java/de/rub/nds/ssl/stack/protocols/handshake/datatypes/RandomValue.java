package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Random value message part - as defined in RFC-2246.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Nov 15, 2011
 */
public final class RandomValue extends APubliclySerializable {

    /**
     * Length of the random value: 28 Bytes.
     */
    private static final int LENGTH_RANDOM_VALUE = 28;
    /**
     * Length of the UNIX timestamp: 4 Bytes.
     */
    private static final int LENGTH_UNIX_TIMESTAMP = 4;
    /**
     * Length of the encoded form.
     */
    public static final int LENGTH_ENCODED = LENGTH_RANDOM_VALUE
            + LENGTH_UNIX_TIMESTAMP;
    /**
     * Random value - 28 bytes secure random.
     */
    private byte[] value = new byte[LENGTH_RANDOM_VALUE];
    /**
     * Unix timestamp - 32 bit UNIX timestamp = 4 bytes.
     */
    private byte[] unixTimestamp = new byte[LENGTH_UNIX_TIMESTAMP];
    
    public String toString() {
    	return "RandomValue: " + Utility.bytesToInt(unixTimestamp) +
                " " + Utility.bytesToHex(value);
    }

    /**
     * Initializes a random value object as defined in RFC-2246.
     */
    public RandomValue() {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(value);

        // convert unix timepstamp (32 bit == 4 Byte)
        ByteBuffer timeStampBuffer = ByteBuffer.allocate(8); // long = 8 Bytes!
        timeStampBuffer.order(ByteOrder.BIG_ENDIAN);
        timeStampBuffer.putLong(System.currentTimeMillis());
        unixTimestamp = timeStampBuffer.array();
    }

    /**
     * Initializes a random value object as defined in RFC-2246.
     *
     * @param message Random value in encoded form
     */
    public RandomValue(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Get the random value of this message.
     *
     * @return The random value of this message
     */
    public byte[] getValue() {
        // deep copy
        byte[] tmp = new byte[value.length];
        System.arraycopy(value, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the random value of this message.
     *
     * @param randomValue The random value to be used for this message
     */
    public final void setValue(final byte[] randomValue) {
        if (randomValue == null) {
            throw new IllegalArgumentException("Random value"
                    + "must not be null!");
        }

        // deep copy
        this.value = new byte[randomValue.length];
        System.arraycopy(randomValue, 0, this.value, 0, randomValue.length);
    }

    /**
     * Get the UNIX timestamp of this message.
     *
     * @return The timestamp of this message
     */
    public byte[] getUnixTimestamp() {
        // deep copy
        byte[] tmp = new byte[unixTimestamp.length];
        System.arraycopy(unixTimestamp, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the UNIX timestamp of this message.
     *
     * @param unixTimestamp The timestamp to be used for this message
     */
    public void setUnixTimestamp(final byte[] unixTimestamp) {
        if (unixTimestamp == null) {
            throw new IllegalArgumentException("Timestamp must not be null!");
        }

        if (unixTimestamp.length != LENGTH_UNIX_TIMESTAMP) {
            throw new IllegalArgumentException("Timestamps"
                    + "must be 4 bytes long");
        }

        // deep copy
        this.unixTimestamp = new byte[unixTimestamp.length];
        System.arraycopy(unixTimestamp, 0, this.unixTimestamp, 0,
                unixTimestamp.length);
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public byte[] encode(final boolean chained) {
        byte[] tmp = new byte[LENGTH_ENCODED];
        System.arraycopy(unixTimestamp, 0, tmp, 0, LENGTH_UNIX_TIMESTAMP);
        System.arraycopy(value, 0, tmp, LENGTH_UNIX_TIMESTAMP,
                LENGTH_RANDOM_VALUE);

        return tmp;
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained decoding.
     */
    public void decode(final byte[] message, final boolean chained) {
        // deep copy
        final byte[] random = new byte[message.length];
        System.arraycopy(message, 0, random, 0, random.length);

        // check size
        if (random.length < LENGTH_ENCODED) {
            throw new IllegalArgumentException("Random record too short.");
        } else if (random.length > LENGTH_ENCODED) {
            throw new IllegalArgumentException("Random record too long.");
        }

        System.arraycopy(random, 0, this.unixTimestamp,
                0, LENGTH_UNIX_TIMESTAMP);
        System.arraycopy(random, LENGTH_UNIX_TIMESTAMP, this.value, 0,
                LENGTH_RANDOM_VALUE);
    }
}
