package de.rub.nds.ssl.analyzer.parameters;

import de.rub.nds.ssl.stack.Utility;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.log4j.Logger;

/**
 * Defines the ChangeCipherSpec parameters for tests.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum
 * @version 0.1 Jun. 21, 2012
 */
public final class ChangeCipherSpecParams extends AParameters {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();
    /**
     * ChangeCipherSpec payload.
     */
    private byte[] payload;

    /**
     * Get the value of the ChangeCipherSpec payload.
     *
     * @return ChangeCipherSpec payload
     */
    public byte[] getPayload() {
        byte[] result = null;
        if (this.payload != null) {
            result = new byte[this.payload.length];
            System.arraycopy(this.payload, 0, result, 0, result.length);
        }

        return result;
    }

    /**
     * Set the value of the ChangeCipherSpec payload.
     *
     * @param payload ChangeCipherSpec payload
     */
    public void setPayload(final byte[] payload) {
        if (payload != null) {
            this.payload = new byte[payload.length];
            System.arraycopy(payload, 0, this.payload, 0,
                    this.payload.length);
        }
        else
        	this.payload = null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String computeHash() {
        MessageDigest sha1 = null;
        try {
            sha1 = MessageDigest.getInstance("SHA");
        } catch (NoSuchAlgorithmException e) {
            logger.error("Wrong algorithm.", e);
        }
        updateHash(sha1, getIdentifier().name().getBytes());
        updateHash(sha1, getDescription().getBytes());
        updateHash(sha1, getPayload());
        byte[] hash = sha1.digest();
        String hashValue = Utility.bytesToHex(hash);
        hashValue = hashValue.replace(" ", "");
        return hashValue;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void updateHash(final MessageDigest md, final byte[] input) {
        if (input != null) {
            md.update(input);
        }
    }
}
