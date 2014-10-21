package de.rub.nds.ssl.stack.protocols.handshake.extensions;

import de.rub.nds.ssl.stack.protocols.commons.Id;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECPointFormat;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;

import java.util.*;

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
    private List<EECPointFormat> supportedPointFormats = new LinkedList<>();

    private List<Id> rawPointFormats = new LinkedList<>();

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
        this.decode(message, true);
    }

    /**
     * Get the supported point formats.
     *
     * @return Supported EC point formats.
     */
    public List<EECPointFormat> getSupportedPointFormats() {
        return new ArrayList<>(supportedPointFormats);
    }

    public List<Id> getRawPointFormats() {
        return new ArrayList<>(rawPointFormats);
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

        this.supportedPointFormats = Arrays.asList(formats);

        this.rawPointFormats = new ArrayList<>(formats.length);
        for(EECPointFormat pf : formats) {
            rawPointFormats.add(new Id(pf.getId()));
        }
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
        Integer formatBytes = supportedPointFormats.size()
                * EECPointFormat.LENGTH_ENCODED;
        byte[] tmp = new byte[LENGTH_LENGTH_FIELD + formatBytes];
        byte[] length;

        // length
        length = buildLength(formatBytes, LENGTH_LENGTH_FIELD);
        System.arraycopy(length, 0, tmp, pointer, length.length);
        pointer += length.length;
        
        for (int i = 0; i < supportedPointFormats.size(); i++) {
            tmp[i + pointer] = supportedPointFormats.get(i).getId();
        }
        
        setExtensionData(tmp);
        return super.encode(true);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        if(chained)
            super.decode(message, chained);
        else
            setExtensionData(message);

        final int formatsCount;
        final byte[] tmp = getExtensionData();

        rawPointFormats = new LinkedList<>();
        supportedPointFormats = new LinkedList<>();
        
        // check size
        if (tmp.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException(
                    "EC Point Formats extension too short.");
        }
        
        formatsCount = (extractLength(tmp, 0, LENGTH_LENGTH_FIELD)) & 0xff;
        if (tmp.length - LENGTH_LENGTH_FIELD !=
                formatsCount * EECPointFormat.LENGTH_ENCODED) {
            throw new IllegalArgumentException(
                    "EC Point Formats extension length invalid.");
        }

        // extract point formats
        for (int j = 0; j < formatsCount; j++) {
            final byte id = tmp[j + LENGTH_LENGTH_FIELD];
            rawPointFormats.add(new Id(id));
            supportedPointFormats.add(EECPointFormat.getECPointFormat(id));
        }
    }
}
