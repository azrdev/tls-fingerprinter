package de.rub.nds.ssl.stack.protocols.handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;

/**
 * List of extensions after the standard ClientHello fields.
 * 
 * @author Erik Tews
 *
 */
public class ExtensionList extends APubliclySerializable {

	/**
	 * List of extensions supported, so we can access them using the reflections
	 * API. All other extensions can be handled by the GenericExtension Class.
	 */
	static Map<Integer, Class<? extends Extension>> supported_extensions = new HashMap<Integer, Class<? extends Extension>>();
	static {
		supported_extensions.put(0, ServerNameExtension.class);
	}

	// Our extensions
	ArrayList<Extension> extensions = new ArrayList<Extension>();

	@SuppressWarnings("unchecked")
	public List<Extension> getExtensions() {
		return (List<Extension>) extensions.clone();
	}
	
	

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((extensions == null) ? 0 : extensions.hashCode());
		return result;
	}



	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ExtensionList other = (ExtensionList) obj;
		if (extensions == null) {
			if (other.extensions != null)
				return false;
		} else if (!extensions.equals(other.extensions))
			return false;
		return true;
	}



	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("ExtensionList with " + extensions.size() + " extensions:");
		for (Extension e : extensions) {
			sb.append("\n" + e.toString());
		}
		return new String(sb);
	}

	@Override
	public byte[] encode(boolean chained) {
		try {
			byte[][] results = new byte[extensions.size()][];
			int i = 0;
			int l = 0;
			for (Extension extension : extensions) {
				results[i] = extension.encode(false);
				l += results[i].length;
				i++;
			}
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			bos.write(this.buildLength(l, 2));
			for (int j = 0; j < results.length; j++) {
				bos.write(results[i]);
			}
			return bos.toByteArray();
		} catch (IOException e) {
			// Should never happen
			throw new RuntimeException(e);
		}
	}

	@Override
	public void decode(byte[] message, boolean chained) {
		int pointer = 0;
		int listLen = this.extractLength(message, pointer, 2);
		// System.err.println("list length is " + listLen);
		pointer += 2;
		while (pointer < listLen) {
			int type = this.extractLength(message, pointer, 2);
			int l = this.extractLength(message, pointer + 2, 2);
			// System.err.println("entry of length " + l);
			byte[] data = new byte[l];
			System.arraycopy(message, pointer + 4, data, 0, l);
			Class<? extends Extension> c = supported_extensions.get(type);
			Extension ex = null;
			if (c != null) {
				try {
					ex = c.newInstance();
				} catch (Exception e) {
					e.printStackTrace();
					throw new RuntimeException(e);
				}
			} else {
				ex = new GenericExtension();
				ex.setType(type);
			}
			ex.decode(data, false);
			extensions.add(ex);
			pointer += l + 4;
		}

	}

}
