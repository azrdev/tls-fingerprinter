package de.rub.nds.ssl.stack.protocols.handshake;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class GenericExtension extends Extension {

	/**
	 * All extensions with their names we know.
	 */
	private static Map<Integer, String> extension_names = new HashMap<Integer, String>();
	static {
		extension_names.put(0, "server_name");
		extension_names.put(1, "max_fragment_length");
		extension_names.put(2, "client_certificate_url");
		extension_names.put(3, "trusted_ca_keys");
		extension_names.put(4, "truncated_hmac");
		extension_names.put(5, "status_request");
		extension_names.put(6, "user_mapping");
		extension_names.put(7, "client_authz");
		extension_names.put(8, "server_authz");
		extension_names.put(9, "cert_type");
		extension_names.put(10, "elliptic_curves");
		extension_names.put(11, "ec_point_formats");
		extension_names.put(12, "srp");
		extension_names.put(13, "signature_algorithms");
		extension_names.put(14, "use_srtp");
		extension_names.put(15, "Heartbeat");
		extension_names.put(35, "SessionTicket TLS");
		extension_names.put(13172, "next_protocol_negotiation");
		extension_names.put(65281, "renegotiation_info");
	}

	private byte[] extension_data;

	public String toString() {
		return "GenericExtension of type " + getType() + "("
				+ extension_names.get(getType()) + ") of length "
				+ extension_data.length;
	}

	@Override
	protected void decode_content(byte[] content) {
		this.extension_data = content.clone();

	}
	
	public boolean equals(Object o) {
		if (o instanceof GenericExtension) {
			GenericExtension ge = (GenericExtension) o;
			return (this.getType() == ge.getType()) && Arrays.equals(ge.extension_data, extension_data);
		} else {
			return super.equals(o);
		}
	}

	@Override
	protected byte[] encode_content() {
		return extension_data.clone();
	}

}
