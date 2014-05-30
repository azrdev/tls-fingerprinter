package de.rub.nds.ssl.stack.exceptions;

import de.rub.nds.ssl.stack.Utility;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class UnknownHandshakeMessageTypeException extends IllegalArgumentException {
    public UnknownHandshakeMessageTypeException(byte id) {
        super(String.format("Handshake message type with ID 0x%s (%d) not registered",
                Utility.bytesToHex(id), 0xff & id));
    }
}
