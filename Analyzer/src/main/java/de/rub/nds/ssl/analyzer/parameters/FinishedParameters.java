package de.rub.nds.ssl.analyzer.parameters;

import de.rub.nds.ssl.stack.Utility;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.log4j.Logger;

/**
 * Defines the Finished message parameters for tests.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 07, 2012
 */
public final class FinishedParameters extends AParameters {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();
    /**
     * Destroy the MAC of the Finished message.
     */
    private boolean destroyMAC = false;
    /**
     * Destroy the hash value of the handshake messages.
     */
    private boolean destroyHash = false;
    /**
     * Destroy the verify data of the Finished message.
     */
    private boolean destroyVerify = false;
    /**
     * Change the length byte of the padding string.
     */
    private boolean changePadLength = false;
    /**
     * Change the padding string.
     */
    private boolean changePadding = false;

    /**
     * Signalizes if padding string should be changed.
     *
     * @return True if padding string should be changed.
     */
    public boolean isChangePadding() {
        return changePadding;
    }

    /**
     * Set true if padding string should be changed.
     *
     * @param changePadding True if padding string should be changed.
     */
    public void setChangePadding(final boolean changePadding) {
        this.changePadding = changePadding;
    }

    /**
     * Signalizes if MAC value should be destroyed.
     *
     * @return True if MAC is destroyed.
     */
    public boolean isDestroyMAC() {
        return destroyMAC;
    }

    /**
     * Set true if MAC should be destroyed.
     *
     * @param destroyMAC True if MAC is destroyed.
     */
    public void setDestroyMAC(final boolean destroyMAC) {
        this.destroyMAC = destroyMAC;
    }

    /**
     * Signalizes if hash value should be destroyed.
     *
     * @return True if hash is destroyed.
     */
    public boolean isDestroyHash() {
        return destroyHash;
    }

    /**
     * Set true if hash should be destroyed.
     *
     * @param destroyMAC True if hash is destroyed.
     */
    public void setDestroyHash(final boolean destroyHash) {
        this.destroyHash = destroyHash;
    }

    /**
     * Signalizes if Verify Data value should be destroyed.
     *
     * @return True if Verify Data is destroyed.
     */
    public boolean isDestroyVerify() {
        return destroyVerify;
    }

    /**
     * Set true if Verify Data should be destroyed.
     *
     * @param destroyMAC True if Verify Data is destroyed.
     */
    public void setDestroyVerify(final boolean destroyVerify) {
        this.destroyVerify = destroyVerify;
    }

    /**
     * Signalizes if padding length byte is changed.
     *
     * @return True if padding length byte is changed
     */
    public boolean isChangePadLength() {
        return changePadLength;
    }

    /**
     * Set to true if padding length byte should be changed.
     *
     * @param changePadLength True if padding length byte is changed
     */
    public void setChangePadLength(final boolean changePadLength) {
        this.changePadLength = changePadLength;
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
        updateHash(sha1, String.valueOf(isDestroyMAC()).getBytes());
        updateHash(sha1, String.valueOf(isDestroyHash()).getBytes());
        updateHash(sha1, String.valueOf(isChangePadLength()).getBytes());
        updateHash(sha1, String.valueOf(isChangePadding()).getBytes());
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
