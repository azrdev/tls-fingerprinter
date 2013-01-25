package de.rub.nds.ssl.analyzer.parameters;

import de.rub.nds.ssl.stack.Utility;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.log4j.Logger;

/**
 * Defines the record/handshake header parameters.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 01, 2012
 */
public final class HeaderParameters extends AParameters {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();
    /**
     * Header message type.
     */
    private byte[] msgType;
    /**
     * Protocol version.
     */
    private byte[] protocolVersion;
    /**
     * Header length field.
     */
    private byte[] recordLength;

    /**
     * Get the header message type.
     *
     * @return Message type
     */
    public byte[] getMsgType() {
        byte[] result;
        if (this.msgType != null) {
            result = new byte[this.msgType.length];
            System.arraycopy(this.msgType, 0, result, 0, result.length);
        } else {
            result = new byte[0];
        }

        return result;
    }

    /**
     * Set the header message type.
     *
     * @param msgType Message type
     */
    public void setMsgType(final byte[] msgType) {
        if (msgType != null) {
            this.msgType = new byte[msgType.length];
            System.arraycopy(msgType, 0, this.msgType, 0,
                    this.msgType.length);
        }
    }

    /**
     * Get the protocol version.
     *
     * @return Protocol version
     */
    public byte[] getProtocolVersion() {
        byte[] result;
        if (this.protocolVersion != null) {
            result = new byte[this.protocolVersion.length];
            System.arraycopy(this.protocolVersion, 0, result, 0, result.length);
        } else {
            result = new byte[0];
        }

        return result;
    }

    /**
     * Set the protocol version.
     *
     * @param protocolVersion Protocol version
     */
    public void setProtocolVersion(final byte[] protocolVersion) {
        if (protocolVersion != null) {
            this.protocolVersion = new byte[protocolVersion.length];
            System.arraycopy(protocolVersion, 0, this.protocolVersion, 0,
                    this.protocolVersion.length);
        }
    }

    /**
     * Get the length field value of a header.
     *
     * @return Length of the record
     */
    public byte[] getRecordLength() {
        byte[] result;
        if (this.recordLength != null) {
            result = new byte[this.recordLength.length];
            System.arraycopy(this.recordLength, 0, result, 0, result.length);
        } else {
            result = new byte[0];
        }

        return result;
    }

    /**
     * Set the length field value of the a header.
     *
     * @param recordLength Length of the record
     */
    public void setRecordLength(final byte[] recordLength) {
        if (recordLength != null) {
            this.recordLength = new byte[recordLength.length];
            System.arraycopy(recordLength, 0, this.recordLength, 0,
                    this.recordLength.length);
        }
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
        updateHash(sha1, getMsgType());
        updateHash(sha1, getProtocolVersion());
        updateHash(sha1, getRecordLength());
        byte[] hash = sha1.digest();
        String hashValue = Utility.bytesToHex(hash);
        hashValue = hashValue.replace(" ", "");
        return hashValue;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void updateHash(final MessageDigest sha1, final byte[] input) {
        if (input != null) {
            sha1.update(input);
        }
    }
}
