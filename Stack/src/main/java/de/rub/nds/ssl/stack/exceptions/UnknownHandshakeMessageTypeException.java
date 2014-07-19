package de.rub.nds.ssl.stack.exceptions;

import de.rub.nds.ssl.stack.Utility;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class UnknownHandshakeMessageTypeException extends IllegalArgumentException {
    public UnknownHandshakeMessageTypeException(byte id) {
        super(String.format("Handshake message type with ID %s not registered",
                Utility.bytesIdToHex(id)));
    }
}
