package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;

/**
 * Abstract Server Name prototype for Server Name Extension, as defined in RFC6066.
 *
 * @author jBiegert azrdev@qrdn.de
 */
public abstract class AServerName extends APubliclySerializable {

    /**
     * Length of the Name Type field.
     */
	public static final int LENGTH_NAME_TYPE = ENameType.LENGTH_ENCODED;
    /**
     * Length header of name data.
     */
    public static final int LENGTH_BYTES = 2;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = LENGTH_NAME_TYPE + LENGTH_BYTES;
    /**
     * Type of this server name.
     */
    protected ENameType nameType;
    /**
     * Data (payload) of this Server Name.
     */
    protected byte[] nameData;

    /**
     * Initializes a Server Name as defined in RFC 6066.
     */
    protected AServerName() {
        super();
    }

    /**
     * Initializes a Server Name as defined in RFC 4366.
     *
     * @param nameData Data (payload) of this server name.
     */
    public AServerName(final byte[] nameData) {
        this.decode(nameData, false);
    }

	public ENameType getNameType() { return nameType;}

	protected final void setNameType(final ENameType nameType) {
		if(nameType == null)
			throw new IllegalArgumentException("Name Type must not be null");

		this.nameType = nameType;
	}

	public byte[] getNameData() { return nameData; }

	protected final void setNameData(final byte[] nameData) {
		this.nameData = nameData;
	}

	/**
	 * {@inheritDoc}
	 * @param chained <b>ignored</b>, chained encoding not supported
	 */
	@Override
	public byte[] encode(boolean chained) {
		final byte[] nameData = getNameData();
		byte[] nameBytes = new byte[LENGTH_MINIMUM_ENCODED + nameData.length];
		int pointer = 0;

		// 1. name type
		nameBytes[pointer] = nameType.getId();
		pointer += LENGTH_NAME_TYPE;

		// 2. name data length
		byte[] lengthBytes = buildLength(nameData.length, LENGTH_BYTES);
		System.arraycopy(lengthBytes, 0, nameBytes, pointer, lengthBytes.length);
		pointer += LENGTH_BYTES;

		// 3. name data
		System.arraycopy(nameData, 0, nameBytes, pointer, nameData.length);

		return nameBytes;
	}

	/**
	 * {@inheritDoc}
	 * @param chained <b>ignored</b>, chained encoding not supported
	 */
	@Override
	public void decode(byte[] message, boolean chained) {
		int pointer = 0;

		if(message.length < LENGTH_MINIMUM_ENCODED)
			throw new IllegalArgumentException("Server Name too short");

		// 1. name type
		setNameType(ENameType.getNameType(message[pointer]));
		pointer += LENGTH_NAME_TYPE;

		/*

		// 2. name data length
		int extractedLength = extractLength(message, pointer, LENGTH_BYTES);
		pointer += LENGTH_BYTES;
		if(pointer + extractedLength > message.length)
			throw new IllegalArgumentException("Server Name length invalid");

		// 3. name data
		byte[] tmp = new byte[extractedLength];
		System.arraycopy(message, pointer, tmp, 0, tmp.length);

		*/
		byte[] tmp = new byte[message.length - pointer];
		System.arraycopy(message, pointer, tmp, 0, tmp.length);
		setNameData(tmp);

		// decoding of nameData is done by subclass.decode(), which starts by calling us
	}
}
