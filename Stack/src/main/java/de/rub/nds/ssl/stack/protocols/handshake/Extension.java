package de.rub.nds.ssl.stack.protocols.handshake;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;

public abstract class Extension extends APubliclySerializable {
	private int extension_type;
	
	public final int getType() {
		return this.extension_type;
	}
	
	
	
	protected abstract void decode_content(byte[] content);
	protected abstract byte[] encode_content();
	
	@Override
	public byte[] encode(boolean chained) {
		byte[] extension_data = this.encode_content();
		byte[] result = new byte[extension_data.length + 4];
		byte[] length = buildLength(extension_data.length, 2);
		byte[] type = buildLength(extension_type, 2);
		System.arraycopy(type, 0, result, 0, 2);
		System.arraycopy(length, 0, result, 2, 2);
		System.arraycopy(extension_data, 0, result, 4, extension_data.length);
		return result;
		
	}
	
	public void setType(int type) {
		this.extension_type = type;
	}
	
	@Override
	public void decode(byte[] message, boolean chained) {
		
		// extension_type = extractLength(message, 0, 2);
		// byte[] extension_data = new byte[extractLength(message, 2, 2)];
		// System.arraycopy(message, 4, extension_data, 0, extension_data.length);
		this.decode_content(message);

	}
}
