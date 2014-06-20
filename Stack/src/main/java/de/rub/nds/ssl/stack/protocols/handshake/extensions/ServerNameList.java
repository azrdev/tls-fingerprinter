package de.rub.nds.ssl.stack.protocols.handshake.extensions;

import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.AServerName;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ENameType;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.exceptions.UnknownServerNameType;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * Server Name extension as defined in RFC 6066
 *
 * @author jBiegert azrdev@qrdn.de
 */
public final class ServerNameList extends AExtension {
    /**
     * Length of the length field.
     */
    private static final int LENGTH_LENGTH_FIELD = 2;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = LENGTH_LENGTH_FIELD;

	private List<AServerName> serverNames;

    /**
     * Initializes a Server Name Extension as defined in RFC 6066.
     * No Server Name is added by default at construction time.
     */
	public ServerNameList() {
		this.serverNames = new ArrayList<>(1);
		setExtensionType(EExtensionType.SERVER_NAME);
	}

    /**
     * Initializes a Server Name Extension as defined in RFC 6066.
     *
     * @param message Server Name Extension in encoded form
     */
	public ServerNameList(final byte[] message) {
		this.serverNames = new ArrayList<>(1);
		this.decode(message, false);
	}

	public List<AServerName> getServerNames() {
		return serverNames;
	}

	public void setServerNames(List<AServerName> serverNames) {
		this.serverNames = serverNames;
	}

	/**
	 * {@inheritDoc}
	 * @param chained <b>ignored</b>, chained encoding not supported
	 */
	@Override
	public byte[] encode(boolean chained) {
		// encode all the names & determine encoded length
		int length = 0;
		final List<byte[]> encodedNames = new ArrayList<>(serverNames.size());
		for(AServerName name : serverNames) {
			byte[] encodedName = name.encode(chained);
			encodedNames.add(encodedName);
			length += encodedName.length;
		}

		// allocate output buffer
		byte[] extensionBytes = new byte[LENGTH_LENGTH_FIELD + length];
		int pointer = 0;

		// encode length
		final byte[] encodedLength = buildLength(length, LENGTH_LENGTH_FIELD);
		System.arraycopy(encodedLength, 0, extensionBytes, pointer, encodedLength.length);

		// append encoded names
		for(byte[] encodedName : encodedNames) {
			System.arraycopy(encodedName, 0, extensionBytes, pointer, encodedName.length);
			pointer += encodedName.length;
		}

		// pass data to Extension.encode()
		setExtensionData(extensionBytes);
		return super.encode(chained);
	}

	/**
	 * {@inheritDoc}
	 * @param chained <b>ignored</b>, chained decoding not supported
	 */
	@Override
	public void decode(final byte[] message, final boolean chained) {
		super.decode(message, chained);
		final byte[] rawNames = getExtensionData();
		int pointer = 0;

		// check length
		if(rawNames.length < LENGTH_MINIMUM_ENCODED)
			throw new IllegalArgumentException("Server Name extension too short");

		// extract length
		final int namesLength = extractLength(rawNames, pointer, LENGTH_LENGTH_FIELD);
		pointer += LENGTH_LENGTH_FIELD;

		if(namesLength + pointer != rawNames.length)
			throw new IllegalArgumentException("Server Name List has wrong length");

		// extract each name
		while(pointer + ENameType.LENGTH_ENCODED <= rawNames.length) {
			//TODO: this duplicates AServerName.decode()
			ENameType nameType = null;
			int extractedLength;
			int namePointer = 0;

			// 1. get name_type
			try {
				nameType = ENameType.getNameType(rawNames[pointer]);
			} catch (UnknownServerNameType e) {
				//XXX: logging?
			}
			namePointer += AServerName.LENGTH_NAME_TYPE;

			// 2. get name data length
			extractedLength = extractLength(rawNames,
					pointer + namePointer,
					AServerName.LENGTH_BYTES);
			namePointer += AServerName.LENGTH_BYTES;
			if(extractedLength + pointer + namePointer > rawNames.length)
				throw new IllegalArgumentException("Name Data too short");

			// 3. get (raw) name data
			byte[] nameData =
					new byte[AServerName.LENGTH_MINIMUM_ENCODED + extractedLength];
			System.arraycopy(rawNames, pointer, nameData, 0, nameData.length);
			namePointer += nameData.length;

			// 4. delegate name data decoding & add decoded name to serverNames
			try {
				serverNames.add(nameType.getInstance(nameData));
			} catch(IllegalArgumentException | NullPointerException e) {
				System.out.println("Could not decode Server Name: " + e); //XXX: logging?
			}
			pointer += namePointer;
		}
	}

}
