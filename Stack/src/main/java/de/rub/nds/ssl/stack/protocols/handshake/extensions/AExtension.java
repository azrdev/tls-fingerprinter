package de.rub.nds.ssl.stack.protocols.handshake.extensions;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;

/**
 * Abstract extension prototype as defined in RFC 4366.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jul 27, 2013
 */
public abstract class AExtension extends APubliclySerializable {
    /**
     * Length of the Extension Type field.
     */
    private static final int LENGTH_EXTENSION_TYPE = EExtensionType.LENGTH_ENCODED;
    /**
     * Length header of extension data.
     */
    public static final int LENGTH_BYTES = 2;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = LENGTH_EXTENSION_TYPE 
            + LENGTH_BYTES;
    /**
     * Type of this extension.
     */
    protected EExtensionType extensionType;
    /**
     * Data (payload) of this extension.
     */
    protected byte[] extensionData;
    
    /**
     * Initializes an Extension as defined in RFC 4366.
     */
    protected AExtension() {
        super();
    }

    /**
     * Initializes an Extension as defined in RFC 4366.
     *
     * @param extensionData Data (payload) of this extension.
     */
    public AExtension(final byte[] extensionData) {
        this.decode(extensionData, false);
    }

    /**
     * Get the extension type of this extension.
     * @return Type of this extension
     */
    public EExtensionType getExtensionType() {
        // deep copy
        return EExtensionType.valueOf(extensionType.name());
    }

    /**
     * Set the extension type of this extension.
     * @param extensionType The extension type to set
     */
    protected final void setExtensionType(final EExtensionType extensionType) {
        if (extensionType == null) {
            throw new IllegalArgumentException(
                    "Extension type must not be null!");
        }

        // deep copy
        this.extensionType = EExtensionType.valueOf(extensionType.name());
    }

    /**
     * Get the data of this extension.
     * @return Data of this extension
     */
    public byte[] getExtensionData() {
        // deep copy
        byte[] tmp = new byte[extensionData.length];
        System.arraycopy(extensionData, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Set the extension data of this extension.
     * @param extensionData The extension data to set
     */
    protected final void setExtensionData(final byte[] extensionData) {
        if (extensionData != null) {
            // deep copy
	        this.extensionData = new byte[extensionData.length];
	        System.arraycopy(extensionData, 0,
			        this.extensionData, 0,
	                this.extensionData.length);
        }
    }
    
    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained encoding.
     * AExtension representation 2 byte Extension Type + x bytes Extension Data
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer;
        byte[] tmp;
        final byte[] extensionData = getExtensionData();
        byte[] extensionBytes = new byte[LENGTH_MINIMUM_ENCODED
                + extensionData.length];

        pointer = 0;
        // 1. extension type
        tmp = this.getExtensionType().getId();
        System.arraycopy(tmp, 0, extensionBytes, pointer, tmp.length);
        pointer += tmp.length;

        // 2. extension data length
        tmp = buildLength(extensionData.length, LENGTH_BYTES);
        System.arraycopy(tmp, 0, extensionBytes, pointer, tmp.length);
        pointer += tmp.length;

        // 3. extension data
        tmp = extensionData;
        System.arraycopy(tmp, 0, extensionBytes, pointer, tmp.length);

        return extensionBytes;
    }

    /**
     * {@inheritDoc}
     * 
     * Method parameter will be ignored - no support for chained decoding.
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        final byte[] messageCopy;
        byte[] tmpBytes;
        int pointer;
        int extractedLength;

        // check size
        if (message.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException("Extension too short.");
        }

        //deep copy
        messageCopy = new byte[message.length];
        System.arraycopy(message, 0, messageCopy, 0, messageCopy.length);
        
        pointer = 0;
        // 1. extension type
        tmpBytes = new byte[EExtensionType.LENGTH_ENCODED];
        System.arraycopy(messageCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setExtensionType(EExtensionType.getExtension(tmpBytes));
        pointer += tmpBytes.length;

        // 2. extension data length
        extractedLength = extractLength(messageCopy, pointer, LENGTH_BYTES);
	    pointer += LENGTH_BYTES;
        if (pointer + extractedLength > messageCopy.length) {
            throw new IllegalArgumentException("Extension data length invalid.");
        }

	    // 3. extension data
        tmpBytes = new byte[extractedLength];
        System.arraycopy(messageCopy, pointer, tmpBytes, 0, tmpBytes.length);
        setExtensionData(tmpBytes);
	    // decoding of extension data is done by subclass, using getExtensionData()
    }
}
