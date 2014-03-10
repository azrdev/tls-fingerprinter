package de.rub.nds.ssl.stack.workflows.commons;

import de.rub.nds.ssl.stack.Utility;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Hash computation of the handshake messages.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @author Oliver Domke - oliver.domke@ruhr-uni-bochum.de
 * @version 0.2
 * 
 * Feb 05, 2014
 */
public class HandshakeHashBuilder {

    /**
     * Hash functions.
     */
    private MessageDigest md5, sha1;

    /**
     * Initialize the hash functions.
     *
     * @throws NoSuchAlgorithmException
     */
    public HandshakeHashBuilder() throws NoSuchAlgorithmException {
        md5 = MessageDigest.getInstance("MD5");
        sha1 = MessageDigest.getInstance("SHA");
        md5.reset();
        sha1.reset();
    }

    /**
     * Update the hash value.
     *
     * @param msg Current handshake message
     * @param offset Offset of the message
     * @param len Length of bytes to hash
     */
    public final void updateHash(final byte[] msg, final int offset,
            final int len) {
        md5.update(msg, offset, len);
        sha1.update(msg, offset, len);
    }

    /**
     * Get hash over exchanged handshake messages.
     *
     * @return Hash value over the handshake messages
     * @throws DigestException Digest exception
     */
    public final byte[] getHandshakeMsgsHashes() throws DigestException {
        int md5Length = md5.getDigestLength();
        int sha1Length = sha1.getDigestLength();
        byte[] handshakeHashes = new byte[md5Length + sha1Length];
        md5.digest(handshakeHashes, 0, md5Length);
        sha1.digest(handshakeHashes, md5Length, sha1Length);
        return handshakeHashes;
    }
    
    public final void reset(){
        md5.reset();
        sha1.reset();
    }
}
