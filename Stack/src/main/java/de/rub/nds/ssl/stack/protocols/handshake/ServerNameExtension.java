package de.rub.nds.ssl.stack.protocols.handshake;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

/**
 * Representation of a server name indication extension.
 * 
 * @author Erik Tews
 *
 */
public class ServerNameExtension extends Extension {

	/**
	 * All hostnames contained in that extension.
	 */
	private ArrayList<String> hostNames = new ArrayList<String>();
	private boolean wasZeroLength = false;
	
	public ServerNameExtension() {
		super();
		setType(0);
	}
	
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("ServerNameExtension with " + hostNames.size() + " name(s):");
		for (String s : hostNames) {
			sb.append("\n" + s);
		}
		if(wasZeroLength) {
			sb.append("\nwas zero length");
		}
		return new String(sb);
	}
	
	@Override
	protected void decode_content(byte[] content) {
		// Total length of the list
		if (content.length == 0) {
			this.wasZeroLength = true;
			return;
		}
		int length = this.extractLength(content, 0, 2);
		int pointer = 2;
		
		
		while (pointer < length) {
			// Tag must be 0, other formats are not supported.
			int tag = content[pointer]&0xff;
			if (tag != 0) {
				throw new IllegalArgumentException("found a tag = " + tag + ", pointer = " + pointer);
			}
			
			// Length of the string in UTF-8 encoded form in bytes.
			int slen = this.extractLength(content, pointer+1, 2);
			byte[] sname = new byte[slen];
			System.arraycopy(content, pointer+3, sname, 0, slen);
			
			try {
				hostNames.add(new String(sname, "UTF-8"));
			} catch (UnsupportedEncodingException e) {
				throw new RuntimeException(e);
			}
			
			pointer += slen + 3;
		}

	}

	@Override
	protected byte[] encode_content() {
		try {
			int len = 0;
			for (String s : hostNames) {
				len += s.length() + 3;
			}
			ByteArrayOutputStream bos = new ByteArrayOutputStream(len + 2);
			bos.write(this.buildLength(len, 2));
			for (String s : hostNames) {
				/*
				 * Warning, string length might be different from the length of
				 * the UTF-8 encoded form.
				 */
				bos.write(0);
				byte[] swrite = s.getBytes("UTF-8");
				bos.write(this.buildLength(swrite.length, 2));
				bos.write(swrite);
			}
			return bos.toByteArray();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}
	
	public boolean equals(Object o) {
		if (o instanceof ServerNameExtension) {
			ServerNameExtension sne = (ServerNameExtension) o;
			return sne.hostNames.equals(this.hostNames);
		} else {
			return super.equals(o);
		}
	}
	
	@SuppressWarnings("unchecked")
	public List<String> getServerNames() {
		return (List<String>) hostNames.clone();
	}

}
