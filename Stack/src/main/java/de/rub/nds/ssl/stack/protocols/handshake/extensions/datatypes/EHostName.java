package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;

/**
 * DNS hostname for use in a Server Name Extension (RFC6066)
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class EHostName extends AServerName {

    /**
     * Length of the length field.
     */
    private static final int LENGTH_LENGTH_FIELD = 2;
    /**
     * Minimum length of the encoded form.
     */
	public static final int LENGTH_MINIMUM_ENCODED = LENGTH_LENGTH_FIELD;

	private String hostName;

	private final Charset asciiCharset = StandardCharsets.US_ASCII;

	/**
	 * Initializes a Host Name with an empty String.
	 */
	public EHostName() {}

	/**
	 * Initializes a Host Name.
	 */
	public EHostName(final byte[] encoded) {
		this.decode(encoded, false);
	}

	/**
	 * Set the DNS Host Name
	 * @throws java.lang.IllegalArgumentException if no valid FQDN
	 */
	public void setHostName(String hostName) throws IllegalArgumentException {
		if(! asciiCharset.newEncoder().canEncode(hostName))
			throw new IllegalArgumentException("Host Name must be ASCII only");
		//TODO: IP addresses not allowed, check?
		this.hostName = hostName;
	}

	/**
	 * {@inheritDoc}
	 * @param chained <b>ignored</b>, chained encoding not supported
	 */
	@Override
	public byte[] encode(boolean chained) {
		byte[] encodedName = hostName.getBytes(asciiCharset);
		byte[] encodedLength = buildLength(encodedName.length, LENGTH_LENGTH_FIELD);
		byte[] encoded = new byte[encodedName.length + LENGTH_LENGTH_FIELD];

		System.arraycopy(encodedLength, 0, encoded, 0, encodedLength.length);
		System.arraycopy(encodedName, 0, encoded, encodedLength.length,
				encodedName.length);

		setNameData(encoded);
		return super.encode(true);
	}

	@Override
	public void decode(byte[] message, boolean chained) {
		super.decode(message, chained);

		int pointer = 0;
		final byte[] nameBytes = getNameData();

		// check size
		if(nameBytes.length < LENGTH_MINIMUM_ENCODED)
			throw new IllegalArgumentException("DNS Hostname too short");

		int extractedLength = extractLength(nameBytes, pointer, LENGTH_LENGTH_FIELD);
		pointer += LENGTH_LENGTH_FIELD;

		if((pointer + extractedLength) != nameBytes.length) {
			throw new IllegalArgumentException("Wrong length of DNS hostname");
			//XXX: log instead
		}

		//TODO: this string constructor doesn't throw on non-ascii chars, does setHostName() ?
		setHostName(new String(nameBytes, pointer, extractedLength, asciiCharset));
	}

	public String getHostName() {
		return hostName;
	}

	@Override
	public String toString() {
		return hostName;
	}
}
