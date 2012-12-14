package de.rub.nds.ssl.stack.tests.parameters;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Defines the test parameters used for Vaudenay Test.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 24 May, 2012
 */
public class VaudenayParameters extends AParameters {

    /**
     * Protocol version of finished message.
     */
    private EProtocolVersion protocolVersion;
    /**
     * Signalizes if padding should be changed.
     */
    private boolean changePadding;

    /**
     * Get protocol version of the finished message.
     *
     * @return Protocol version
     */
    public EProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    /**
     * Set protocol version of the finished message.
     *
     * @param protocolVersion Protocol version
     */
    public void setProtocolVersion(EProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    /**
     * Signalizes if padding is changed.
     *
     * @return True if padding is changed
     */
    public boolean isChangePadding() {
        return changePadding;
    }

    /**
     * Set boolean to change the padding.
     *
     * @param changePadding Set to true to change padding
     */
    public void setChangePadding(boolean changePadding) {
        this.changePadding = changePadding;
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
            e.printStackTrace();
        }
        updateHash(sha1, getProtocolVersion().getId());
        updateHash(sha1, String.valueOf(isChangePadding()).getBytes());
        byte[] hash = sha1.digest();
        String hashString = Utility.bytesToHex(hash);
        hashString = hashString.replace(" ", "");
        return hashString;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void updateHash(MessageDigest sha1, byte[] input) {
        if (input != null) {
            sha1.update(input);
        }
    }
}
