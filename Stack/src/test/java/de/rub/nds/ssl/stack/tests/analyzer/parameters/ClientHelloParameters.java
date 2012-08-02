package de.rub.nds.ssl.stack.tests.analyzer.parameters;

import de.rub.nds.ssl.stack.Utility;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Defines the client hello parameters for fingerprinting tests.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Jun 02, 2012
 */
public class ClientHelloParameters extends AParameters {

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
        if (this.protocolVersion != null) {
            return this.protocolVersion.clone();
        } else {
            return null;
        }
    }

    public void setProtocolVersion(byte[] protocolVersion) {
        if (protocolVersion != null) {
            this.protocolVersion = protocolVersion;
        } else {
            this.protocolVersion = null;
        }
    }

    /**
     * Get the session ID value if no sessionID is defined. (Default is 0x00)
     *
     * @return Separate byte
     */
    public byte[] getNoSessionIdValue() {
        if (this.noSessionValue != null) {
            return this.noSessionValue.clone();
        } else {
            return null;
        }
    }

    /**
     * Set the session ID value if no sessionID is defined. (Default is 0x00)
     *
     * @param randomSeparate Separate byte
     */
    public void setNoSessionIdValue(byte[] randomSeparate) {
        if (randomSeparate != null) {
            this.noSessionValue = randomSeparate.clone();
        } else {
            this.noSessionValue = null;
        }
    }

    /**
     * Get the session ID od the ClientHello message.
     *
     * @return Session ID
     */
    public byte[] getSessionId() {
        if (this.sessionId != null) {
            return sessionId.clone();
        } else {
            return null;
        }
    }

    /**
     * Set the session ID od the ClientHello message.
     *
     * @param sessionId Session ID
     */
    public void setSessionId(byte[] sessionId) {
        if (sessionId != null) {
            this.sessionId = sessionId.clone();
        } else {
            this.sessionId = null;
        }
    }

    /**
     * Get the value of the session ID length field.
     *
     * @return Value of the session ID length field
     */
    public byte[] getSessionIdLen() {
        if (this.sessionIdLen != null) {
            return sessionIdLen.clone();
        } else {
            return null;
        }
    }

    /**
     * Set the value of the session ID length field.
     *
     * @param sessionIdLen Value of the session ID length field
     */
    public void setSessionIdLen(byte[] sessionIdLen) {
        if (sessionIdLen != null) {
            this.sessionIdLen = sessionIdLen.clone();
        } else {
            this.sessionIdLen = null;
        }
    }

    /**
     * Get the value of the cipher suite length field.
     *
     * @return Value of the cipher suite length field
     */
    public byte[] getCipherLen() {
        if (this.cipherLen != null) {
            return this.cipherLen.clone();
        } else {
            return null;
        }
    }

    /**
     * Set the value of the cipher suite length field.
     *
     * @param cipherLen Value of the cipher suite length field
     */
    public void setCipherLen(byte[] cipherLen) {
        if (cipherLen != null) {
            this.cipherLen = cipherLen.clone();
        } else {
            this.cipherLen = null;
        }
    }

    /**
     * Get the compression method.
     *
     * @return Compression method
     */
    public byte[] getCompMethod() {
        if (this.compMethod != null) {
            return this.compMethod.clone();
        } else {
            return null;
        }
    }

    /**
     * Set the compression method.
     *
     * @param compMethod Compression method
     */
    public void setCompMethod(byte[] compMethod) {
        if (compMethod != null) {
            this.compMethod = compMethod.clone();
        } else {
            this.compMethod = null;
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
            e.printStackTrace();
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
    public void updateHash(MessageDigest sha1, byte[] input) {
        if (input != null) {
            sha1.update(input);
        }
    }
}
