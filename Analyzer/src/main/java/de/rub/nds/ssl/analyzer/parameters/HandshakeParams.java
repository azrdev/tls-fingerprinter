package de.rub.nds.ssl.analyzer.parameters;

import de.rub.nds.ssl.stack.Utility;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.log4j.Logger;

/**
 * Handshake parameters to detect handshake enumerations.
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 30, 2013
 */
public final class HandshakeParams extends AParameters {

    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();
    /**
     * Continued handshake (enumeration) yes/no.
     */
    private boolean continued;

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
        byte[] bytes = new byte[1];
        if (isContinued()) {
            bytes[0] = 1;
        } else {
            bytes[0] = 0;
        }
        updateHash(sha1, bytes);
        byte[] hash = sha1.digest();
        String hashValue = Utility.bytesToHex(hash);
        hashValue = hashValue.replace(" ", "");
        return hashValue;
    }

    @Override
    public void updateHash(final MessageDigest md, final byte[] input) {
        if (input != null) {
            md.update(input);
        }
    }

    /**
     * Is this handshake continued?
     * @return True if continued.
     */
    public boolean isContinued() {
        return continued;
    }

    /**
     * Setter if this handshake is continued or not.
     * @param continued True if continued
     */
    public void setContinued(final boolean continued) {
        this.continued = continued;
    }
}
