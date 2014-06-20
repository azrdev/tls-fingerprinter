package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.exceptions.UnknownServerNameType;

import java.util.HashMap;
import java.util.Map;

/**
 * (Server) Name Type for a ServerName Extension (RFC6066)
 *
 * @author jBiegert azrdev@qrdn.de
 */
public enum ENameType {
	/**
	 * Server name is a DNS hostname
	 */
	HOST_NAME((byte) 0x00, EHostName.class);

	private final byte id;
	private final Class implementingClass;

	public static final int LENGTH_ENCODED = 1;
	private static final Map<Byte, ENameType> ID_MAP = new HashMap<>(1);

	static {
		for(ENameType type : values()) {
			ID_MAP.put(type.getId(), type);
		}
	}

	private ENameType(final byte id, final Class implementer) {
		this.id = id;
		this.implementingClass = implementer;
	}

	public byte getId() { return id; }

	public static ENameType getNameType(final byte id)
			throws UnknownServerNameType {
		if(!ID_MAP.containsKey(id)) {
			throw new UnknownServerNameType(id);
		}
		return ID_MAP.get(id);
	}

	public Class getImplementingClass() {
		return this.implementingClass;
	}

	public AServerName getInstance(final byte[] message) {
		switch (this) {
			case HOST_NAME:
				return new EHostName(message);
			default:
				throw new IllegalArgumentException("No class implementing " + this);
		}
	}

	@Override
	public String toString() {
		return String.format("ENameType: type %s %s",
				Utility.bytesIdToHex(getId()), name());
	}
}
