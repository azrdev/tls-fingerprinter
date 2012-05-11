package de.rub.nds.research.ssl.stack.protocols.alert;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.research.ssl.stack.protocols.alert.datatypes.EAlertDescription;
import de.rub.nds.research.ssl.stack.protocols.alert.datatypes.EAlertLevel;
import de.rub.nds.research.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.research.ssl.stack.protocols.commons.EProtocolVersion;

/**
 * Defines the Alert message of SSL/TLS as defined in RFC2246
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1 Apr 08, 2012
 */
public class Alert extends ARecordFrame {

    private EAlertLevel level;
    private EAlertDescription desc;

    /**
     * Initializes an Alert message as defined in RFC 2246.
     *
     * @param message Alert message in encoded form
     * @param chained Decode single or chained with underlying frames
     */
    public Alert(final byte[] message, final boolean chained) {
        // dummy call - decoding will invoke decoders of the parents if desired
        super();
        this.decode(message, chained);
    }

    /**
     * Initializes an Alert as defined in RFC 2246
     *
     * @param version Protocol version
     */
    public Alert(final EProtocolVersion version) {
        super(EContentType.ALERT, version);
    }

    /**
     * {@inheritDoc} Alert message containing the alert level and description
     */
    @Override
    public byte[] encode(boolean chained) {
        byte[] alert = new byte[2];

        alert[0] = this.level.getAlertLevelId();
        alert[1] = this.desc.getAlertDescriptionId();

        super.setPayload(alert);
        return chained ? super.encode(true) : alert;
    }

    /**
     * Get the Alert description of the Alert message
     *
     * @return Description of the Alert message
     */
    public EAlertDescription getAlertDescription() {
        return EAlertDescription.valueOf(desc.name());
    }

    /**
     * Get the Alert level of the Alert message
     *
     * @return level of the Alert message
     */
    public EAlertLevel getAlertLevel() {
        return EAlertLevel.valueOf(level.name());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        byte[] payloadCopy;

        if (chained) {
            super.decode(message, true);
        } else {
            setPayload(message);
        }

        // payload already deep copied
        payloadCopy = getPayload();

        //check size
        if (payloadCopy.length > 2 || payloadCopy.length == 0) {
            throw new IllegalArgumentException("Unvalid Alert message");
        }

        // extract alert level
        setAlertLevel(payloadCopy[0]);
        // extract alert description
        setAlertDescription(payloadCopy[1]);
    }

    /**
     * Set the alert level of the Alert message
     *
     * @param Alert level of the message
     */
    public void setAlertLevel(final byte level) {
        this.level = EAlertLevel.getAlertLevel(level);
    }

    /**
     * Set the alert level of the Alert message
     *
     * @param level Alert level
     */
    public void setAlertLevel(EAlertLevel level) {
        this.level = level;
    }

    /**
     * Set the alert description of the Alert message
     *
     * @param Alert description of the message
     */
    public void setAlertDescription(final byte desc) {
        this.desc = EAlertDescription.getAlertDescription(desc);
    }

    /**
     * Set the alert description of the Alert message
     *
     * @param Alert description of the message
     */
    public void setAlertDescription(EAlertDescription desc) {
        this.desc = desc;
    }
}
