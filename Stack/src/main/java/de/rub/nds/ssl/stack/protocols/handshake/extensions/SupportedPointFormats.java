package de.rub.nds.ssl.stack.protocols.handshake.extensions;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECPointFormat;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ENamedCurve;

/**
 * Supported Point Formats extension as defined in RFC 4492.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jul 29, 2013
 */
public final class SupportedPointFormats extends AExtension {

    /**
     * Length of the length field.
     */
    private static final int LENGTH_LENGTH_FIELD = 1;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = LENGTH_LENGTH_FIELD;
    /**
     * Array of supported point formats in preferred order.
     */
    private EECPointFormat[] supportedPointFormats;

    /**
     * Initializes an Supported Point Formats Extension as defined in RFC 4492.
     * All supported point formats are added by default at construction time.
     */
    public SupportedPointFormats() {
        setExtensionType(EExtensionType.EC_POINT_FORMATS);
        setSupportedPointFormats(EECPointFormat.values());
    }

    /**
     * Initializes an Supported Point Formats Extension as defined in RFC 4492.
     *
     * @param message Supported Point Formats Extension in encoded form
     */
    public SupportedPointFormats(final byte[] message) {
        this.decode(message, false);
    }

    /**
     * Get the supported point formats.
     *
     * @return Supported EC point formats.
     */
    public EECPointFormat[] getSupportedPointFormats() {
        // deep copy
        EECPointFormat[] tmp = new EECPointFormat[supportedPointFormats.length];
        System.arraycopy(supportedPointFormats, 0, tmp, 0,
                supportedPointFormats.length);

        return tmp;
    }

    /**
     * Set the supported point Formats.
     *
     * @param formats EC Point Formats to set
     */
    public void setSupportedPointFormats(final EECPointFormat[] formats) {
        if (formats == null) {
            throw new IllegalArgumentException("Formats must not be null!");
        }
        // keep the array clean and small, Mr. Proper will be proud!
        this.supportedPointFormats = new EECPointFormat[formats.length];
        // refill, deep copy
        System.arraycopy(formats, 0, this.supportedPointFormats, 0,
                formats.length);
    }

    /**
     * {@inheritDoc} Supported Point Format representation 1 + x bytes for x
     * formats.
     *
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer = 0;
        Integer formatBytes = supportedPointFormats.length
                * EECPointFormat.LENGTH_ENCODED;
        byte[] tmp = new byte[LENGTH_LENGTH_FIELD + formatBytes];
        byte[] length;

        // length
        length = buildLength(formatBytes, LENGTH_LENGTH_FIELD);
        System.arraycopy(length, 0, tmp, pointer, length.length);
        pointer += length.length;
        
        for (int i = 0; i < supportedPointFormats.length; i++) {
            tmp[i + pointer] = supportedPointFormats[i].getId();
        }
        
        setExtensionData(tmp);
        return super.encode(true);
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained decoding.
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        final int formatsCount;
        // deep copy
        super.decode(message, true);
        final byte[] tmp = getExtensionData();
        
        // check size
        if (tmp.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException(
                    "EC Point Formats extension too short.");
        }
        
        formatsCount = (extractLength(tmp, 0, LENGTH_LENGTH_FIELD)) & 0xff;
        if (tmp.length - LENGTH_LENGTH_FIELD != formatsCount
                * EECPointFormat.LENGTH_ENCODED) {
            throw new IllegalArgumentException(
                    "EC Point Formats extension length invalid.");
        }

        // extract point formats
        EECPointFormat[] extractedPointFormats =
                new EECPointFormat[formatsCount];
        for (int j = 0; j < formatsCount; j++) {
            extractedPointFormats[j] = EECPointFormat.getECPointFormat(
                    tmp[j + LENGTH_LENGTH_FIELD]);
        }
        setSupportedPointFormats(extractedPointFormats);
    }
}
