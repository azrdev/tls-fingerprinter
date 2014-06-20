package de.rub.nds.ssl.stack.protocols.handshake.extensions.exceptions;

import de.rub.nds.ssl.stack.Utility;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class UnknownServerNameType extends IllegalArgumentException {
	public UnknownServerNameType(byte id) {
		super("Unknown NameType for ServerName extension: " +
				Utility.bytesIdToHex(id));
	}
}
