package de.rub.nds.ssl.stack.protocols.alert;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.alert.datatypes.EAlertDescription;
import de.rub.nds.ssl.stack.protocols.alert.datatypes.EAlertLevel;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;

/**
 * Defines the Alert message of SSL/TLS as defined in RFC2246.
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @author Oliver Domke - oliver.domke@ruhr-uni-bochum.de
 * @version 0.2
 * 
 * Feb 05, 2014
 */
public class Alert extends ARecordFrame {

    /**
     * Alert level - fatal/warn.
     */
    private EAlertLevel level;
    /**
     * Alert description.
     */
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
     * Initializes an Alert as defined in RFC 2246.
     *
     * @param version Protocol version
     */
    public Alert(final EProtocolVersion version) {
        super(EContentType.ALERT, version);
    }

    /**
     * {@inheritDoc} Alert message containing the alert level and description.
     */
    @Override
    public final byte[] encode(final boolean chained) {
        byte[] alert = new byte[2];

        alert[0] = this.level.getAlertLevelId();
        alert[1] = this.desc.getId();

        super.setPayload(alert);
        return chained ? super.encode(true) : alert;
    }

    /**
     * Get the Alert description of the Alert message.
     *
     * @return Description of the Alert message
     */
    public final EAlertDescription getAlertDescription() {
        return EAlertDescription.valueOf(desc.name());
    }

    /**
     * Get the Alert level of the Alert message.
     *
     * @return Level of the Alert message
     */
    public final EAlertLevel getAlertLevel() {
        return EAlertLevel.valueOf(level.name());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public final void decode(final byte[] message, final boolean chained) {
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
            throw new IllegalArgumentException("Invalid Alert message! payloadCopy.length == " + payloadCopy.length + ", might be an encrypted alert message");
        }

        // extract alert level
        setAlertLevel(payloadCopy[0]);
        // extract alert description
        setAlertDescription(payloadCopy[1]);
    }

    /**
     * Set the alert level of the Alert message.
     *
     * @param alertLevel Alert level of the message
     */
    public final void setAlertLevel(final byte alertLevel) {
        this.level = EAlertLevel.getAlertLevel(alertLevel);
    }

    /**
     * Set the alert level of the Alert message.
     *
     * @param alertLevel Alert level
     */
    public final void setAlertLevel(final EAlertLevel alertLevel) {
        this.level = alertLevel;
    }

    /**
     * Set the alert description of the Alert message.
     *
     * @param description Alert description of the message
     */
    public final void setAlertDescription(final byte description) {
        this.desc = EAlertDescription.getAlertDescription(description);
    }

    /**
     * Set the alert description of the Alert message.
     *
     * @param description Alert description of the message
     */
    public final void setAlertDescription(final EAlertDescription description) {
        this.desc = description;
    }
}
