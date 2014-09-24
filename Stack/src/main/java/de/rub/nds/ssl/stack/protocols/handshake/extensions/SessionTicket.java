package de.rub.nds.ssl.stack.protocols.handshake.extensions;

import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;

import java.util.Arrays;

/**
 * Session Ticket hello extension from RFC 5077.
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class SessionTicket extends AExtension {
    private byte[] ticket = new byte[0];

    /**
     * Initialize an empty extension object
     */
    public SessionTicket() {
        setExtensionType(EExtensionType.SESSION_TICKET_TLS);
    }

    /**
     * Initialize an extension object from its encoded form
     */
    public SessionTicket(byte[] encoded) {
        this(encoded, true);
    }

    /**
     * Initialize an extension object from its encoded form
     * @param chained Decode single or chained with underlying frames
     */
    public SessionTicket(byte[] encoded, boolean chained) {
        setExtensionType(EExtensionType.SESSION_TICKET_TLS);
        decode(encoded, chained);
    }

    public byte[] getTicket() {
        return ticket;
    }

    public void setTicket(byte[] ticket) {
        if(ticket == null) {
            throw new IllegalArgumentException("ticket must not be null");
        }

        this.ticket = Arrays.copyOf(ticket, ticket.length);
    }

    @Override
    public byte[] encode(boolean chained) {
        setExtensionData(ticket);

        if(chained)
            return super.encode(chained);
        return ticket;
    }

    @Override
    public void decode(byte[] message, boolean chained) {
        byte[] tmp;
        if(chained)
            super.decode(message, chained);
        else
            setExtensionData(message);

        setTicket(getExtensionData());
    }
}
