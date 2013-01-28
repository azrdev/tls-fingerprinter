package de.rub.nds.ssl.analyzer.parameters;

import de.rub.nds.ssl.stack.Utility;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.log4j.Logger;

/**
 * Defines the client hello parameters for tests.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 02, 2012
 */
public final class ClientHelloParameters extends AParameters {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();
    private byte[] protocolVersion = null;
    /**
     * Byte to separate random from the rest of the message.
     */
    private byte[] noSessionValue = null;
    /**
     * Session Id of the ClientHello message.
     */
    private byte[] sessionId = null;
    /**
     * Value of the sessionId length field
     */
    private byte[] sessionIdLen = null;
    /**
     * Value of the cipher suite length field.
     */
    private byte[] cipherLen = null;
    /**
     * Compression method.
     */
    private byte[] compMethod = null;

    public byte[] getProtocolVersion() {
        byte[] result = null;
        if (this.protocolVersion != null) {
            result = new byte[this.protocolVersion.length];
            System.arraycopy(this.protocolVersion, 0, result, 0, result.length);
        }

        return result;
    }

    public void setProtocolVersion(final byte[] protocolVersion) {
        if (protocolVersion != null) {
            this.protocolVersion = new byte[protocolVersion.length];
            System.arraycopy(protocolVersion, 0, this.protocolVersion, 0,
                    this.protocolVersion.length);
        }
        else
        	this.protocolVersion = null;
    }

    /**
     * Get the session ID value if no sessionID is defined. (Default is 0x00)
     *
     * @return Separate byte
     */
    public byte[] getNoSessionIdValue() {
        byte[] result = null;
        if (this.noSessionValue != null) {
            result = new byte[this.noSessionValue.length];
            System.arraycopy(this.noSessionValue, 0, result, 0, result.length);
        }

        return result;
    }

    /**
     * Set the session ID value if no sessionID is defined. (Default is 0x00)
     *
     * @param randomSeparate Separate byte
     */
    public void setNoSessionIdValue(final byte[] randomSeparate) {
        if (randomSeparate != null) {
            this.noSessionValue = new byte[randomSeparate.length];
            System.arraycopy(randomSeparate, 0, this.noSessionValue, 0,
                    this.noSessionValue.length);
        }
        else
        	this.noSessionValue = null;
    }

    /**
     * Get the session ID od the ClientHello message.
     *
     * @return Session ID
     */
    public byte[] getSessionId() {
        byte[] result = null;
        if (this.sessionId != null) {
            result = new byte[this.sessionId.length];
            System.arraycopy(this.sessionId, 0, result, 0, result.length);
        }

        return result;
    }

    /**
     * Set the session ID od the ClientHello message.
     *
     * @param sessionId Session ID
     */
    public void setSessionId(final byte[] sessionId) {
        if (sessionId != null) {
            this.sessionId = new byte[sessionId.length];
            System.arraycopy(sessionId, 0, this.sessionId, 0,
                    this.sessionId.length);
        }
        else
        	this.sessionId = null;
    }

    /**
     * Get the value of the session ID length field.
     *
     * @return Value of the session ID length field
     */
    public byte[] getSessionIdLen() {
        byte[] result = null;
        if (this.sessionIdLen != null) {
            result = new byte[this.sessionIdLen.length];
            System.arraycopy(this.sessionIdLen, 0, result, 0, result.length);
        }

        return result;
    }

    /**
     * Set the value of the session ID length field.
     *
     * @param sessionIdLen Value of the session ID length field
     */
    public void setSessionIdLen(final byte[] sessionIdLen) {
        if (sessionIdLen != null) {
            this.sessionIdLen = new byte[sessionIdLen.length];
            System.arraycopy(sessionIdLen, 0, this.sessionIdLen, 0,
                    this.sessionIdLen.length);
        }
        else
        	this.sessionIdLen = null;
    }

    /**
     * Get the value of the cipher suite length field.
     *
     * @return Value of the cipher suite length field
     */
    public byte[] getCipherLen() {
        byte[] result = null;
        if (this.cipherLen != null) {
            result = new byte[this.cipherLen.length];
            System.arraycopy(this.cipherLen, 0, result, 0, result.length);
        }

        return result;
    }

    /**
     * Set the value of the cipher suite length field.
     *
     * @param cipherLen Value of the cipher suite length field
     */
    public void setCipherLen(final byte[] cipherLen) {
        if (cipherLen != null) {
            this.cipherLen = new byte[cipherLen.length];
            System.arraycopy(cipherLen, 0, this.cipherLen, 0,
                    this.cipherLen.length);
        }
        else
        	this.cipherLen = null;
    }

    /**
     * Get the compression method.
     *
     * @return Compression method
     */
    public byte[] getCompMethod() {
        byte[] result = null;
        if (this.compMethod != null) {
            result = new byte[this.compMethod.length];
            System.arraycopy(this.compMethod, 0, result, 0, result.length);
        }

        return result;
    }

    /**
     * Set the compression method.
     *
     * @param compMethod Compression method
     */
    public void setCompMethod(final byte[] compMethod) {
        if (compMethod != null) {
            this.compMethod = new byte[compMethod.length];
            System.arraycopy(compMethod, 0, this.compMethod, 0,
                    this.compMethod.length);
        }
        else
        	this.compMethod = null;
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
        updateHash(sha1, getProtocolVersion());
        updateHash(sha1, getNoSessionIdValue());
        updateHash(sha1, getSessionId());
        updateHash(sha1, getSessionIdLen());
        updateHash(sha1, getCipherLen());
        updateHash(sha1, getCompMethod());
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
