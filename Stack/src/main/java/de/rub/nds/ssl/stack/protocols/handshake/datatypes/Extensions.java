package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.AExtension;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import java.util.ArrayList;
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
    private List<AExtension> extensions = new ArrayList<>(5);

    /**
     * Initializes an extensions object as defined in RFC-2246. No extensions
     * are added by default at construction time.
     */
    public Extensions() {
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
    public AExtension[] getExtensions() {
        // deep copy
        AExtension[] tmp = new AExtension[extensions.size()];
        extensions.toArray(tmp);

        return tmp;
    }

    /**
     * Set the extensions.
     *
     * @param extensions The extensions to be used
     */
    public final void setExtensions(final List<AExtension> extensions) {
        if (extensions == null) {
            throw new IllegalArgumentException("Extensions must not be null!");
        }

        // new objects keep the array clean and small, Mr. Proper will be proud!
        this.extensions = new ArrayList<>(extensions.size());
        // refill, deep copy list, but not extensions itself!
        this.extensions.addAll(this.extensions);
    }

    /**
     * Add an extension to the extension list
     *
     * @param extension Extension to be added
     */
    public final void addExtension(final AExtension extension) {
        this.extensions.add(extension);
    }

    /**
     * {@inheritDoc} Extensions representation 2 + x*2 bytes for x extensions
     * suites.
     *
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public final byte[] encode(final boolean chained) {
        int pointer = 0;
        List<byte[]> encodedExtensions = new ArrayList<>(extensions.size());
        byte[] tmp;
        for (AExtension tmpExtension : extensions) {
            tmp = tmpExtension.encode(false);
            encodedExtensions.add(tmp);
            pointer += tmp.length;
        }
        
        byte[] extenionBytes = new byte[LENGTH_LENGTH_FIELD + pointer];

        // length
        pointer = 0;
        tmp = buildLength(pointer, LENGTH_LENGTH_FIELD);
        System.arraycopy(tmp, 0, extenionBytes, pointer, tmp.length);
        pointer += tmp.length;

        for (byte[] tmpBytes : encodedExtensions) {
            System.arraycopy(tmpBytes, 0, extenionBytes, pointer,
                    tmpBytes.length);
            pointer += tmpBytes.length;
        }

        return extenionBytes;
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained decoding.
     */
    @Override
    public final void decode(final byte[] message, final boolean chained) {
        int pointer = 0;
        byte[] tmp;
        
        // deep copy
        final byte[] tmpExtensions = new byte[message.length];
        System.arraycopy(message, 0, tmpExtensions, 0, tmpExtensions.length);

        // check size
        if (tmpExtensions.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException(
                    "Extensions record too short.");
        }

        pointer = extractLength(tmpExtensions, 0, LENGTH_LENGTH_FIELD);
        
        // TODO extract extensions!
    }
}
