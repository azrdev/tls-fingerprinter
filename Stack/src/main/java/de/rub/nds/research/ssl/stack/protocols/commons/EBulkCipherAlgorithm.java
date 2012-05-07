package de.rub.nds.research.ssl.stack.protocols.commons;

import java.util.HashMap;
import java.util.Map;

/**
 * Algorithm used for bulk encryption
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1
 * Mar 09, 2012
 */
public enum EBulkCipherAlgorithm {
	NULL("NULL"),
	RC4("RC4"),
	RC2("RC2"),
	DES("DES"),
	TRIPLE_DES("3DES"),
	DES40("DES40"),
	AES("AES");
	
	private String name;
	final private static Map<String, EBulkCipherAlgorithm> ID_MAP =
	            new HashMap<String, EBulkCipherAlgorithm>();
	
	static {
		String name;
        for (EBulkCipherAlgorithm tmp : EBulkCipherAlgorithm.values()) {
            name = tmp.getName();
            ID_MAP.put(name, tmp);
        }
    }
	
	EBulkCipherAlgorithm(String name) {
		this.name=name;
	}
	
	public String getName(){
		return this.name;
	}
	
	public EBulkCipherAlgorithm getBulkCipher(String name){
		return ID_MAP.get(name);
	}
	
	
}
