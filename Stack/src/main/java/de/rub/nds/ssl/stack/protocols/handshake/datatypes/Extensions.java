package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Extensions part - as defined in RFC-3546.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Feb 4, 2013
 */
public class Extensions extends APubliclySerializable {

    /**
     * Length of the length field.
     */
    private static final int LENGTH_LENGTH_FIELD = 2;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = LENGTH_LENGTH_FIELD;
    /**
     * List of all extensions of this object.
     */
    private EExtensionType[] extensions;

    /**
     * {@inheritDoc} 
     */
    @Override
    public String toString() {
        return Arrays.toString(extensions);
    }

    /**
     * Initializes an extensions object as defined in RFC-2246. 
     * All supported extensions are added by default at construction time.
     */
    public Extensions() {
        setExtensions(EExtensionType.values());
    }

    /**
     * Initializes an extension object as defined in RFC-2246.
     *
     * @param extensions Extensions in encoded form
     */
    public Extensions(final byte[] extensions) {
        this.decode(extensions, false);
    }

    /**
     * Get the extensions.
     *
     * @return The extensions of this message
     */
    public EExtensionType[] getExtensions() {
        // deep copy
        EExtensionType[] tmp = new EExtensionType[extensions.length];
        System.arraycopy(extensions, 0, tmp, 0, extensions.length);

        return tmp;
    }

    /**
     * Set the extensions.
     *
     * @param extensions The extensions to be used
     */
    public final void setExtensions(final EExtensionType[] extensions) {
        if (extensions == null) {
            throw new IllegalArgumentException("Extensions must not be null!");
        }

        // new objects keep the array clean and small, Mr. Proper will be proud!
        this.extensions = new EExtensionType[extensions.length];
        // refill, deep copy
        System.arraycopy(extensions, 0, this.extensions, 0, extensions.length);
    }

    /**
     * {@inheritDoc} 
     * Extensions representation 2 + x*2 bytes for x extensions
     * suites.
     *
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer = 0;
        // TODO Extensions are not implemented yet - thus add 2 additional length bytes
        Integer extensionBytes = extensions.length * 
                (EExtensionType.LENGTH_ENCODED+2);
        byte[] tmp = new byte[LENGTH_LENGTH_FIELD + extensionBytes];
        byte[] tmpID = null;

        // length
        tmpID = buildLength(extensionBytes, LENGTH_LENGTH_FIELD);
        System.arraycopy(tmpID, 0, tmp, pointer, tmpID.length);
        //pointer += tmpID.length;

        for (int i = 0, j=EExtensionType.LENGTH_ENCODED; i < extensions.length; i++) {
            tmpID = extensions[i].getId();
            tmp[j] = tmpID[0];
            tmp[j + 1] = tmpID[1];
            
        // TODO Extensions are not implemented yet - thus add 0 length
            tmp[j + 2] = 0;
            tmp[j + 3] = 0;
            j+=4;
        }
        
        return tmp;
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained decoding.
     */
    public void decode(final byte[] message, final boolean chained) {
        // deep copy
        final byte[] tmpExtensions = new byte[message.length];
        System.arraycopy(message, 0, tmpExtensions, 0, tmpExtensions.length);

        // check size
        if (tmpExtensions.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException(
                    "Extensions record too short.");
        }
        
        // extract extensions
        List<EExtensionType> extensions = new ArrayList<EExtensionType>(5);
        int length = 0;
        for (int i = LENGTH_LENGTH_FIELD; i < tmpExtensions.length;) {
            extensions.add(EExtensionType.getExtension(
                    new byte[]{tmpExtensions[i], tmpExtensions[i + 1]}));
            
            // TODO Extensions are not implemented yet - thus skip extension bytes
            length = (extractLength(tmpExtensions, i+2, 2) >> 1) & 0xff;
            i += length + 2 + EExtensionType.LENGTH_ENCODED;
        }
        setExtensions(extensions.toArray(new EExtensionType[extensions.size()]));
    }
}
