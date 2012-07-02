package de.rub.nds.research.ssl.stack.protocols.commons;

import java.util.HashMap;
import java.util.Map;

/**
 * Algorithm used for bulk encryption.
 *
 * @author Eugen Weiss - eugen.weiss@rub.de
 * @version 0.1 Mar 09, 2012
 */
public enum EBulkCipherAlgorithm {

    /**No bulk cipher.*/
    NULL("NULL"),
    /**RC4 bulk cipher.*/
    RC4("RC4"),
    /**RC2 bulk cipher.*/
    RC2("RC2"),
    /**DES bulk cipher.*/
    DES("DES"),
    /**3DES bulk cipher.*/
    TripleDES("3DES"),
    /**DES40 bulk cipher.*/
    DES40("DES40"),
    /**AES bulk cipher.*/
    AES("AES");
    /**Bulk cipher name.*/
    private String name;
    /**Map name to a block cipher.*/
    private static final Map<String, EBulkCipherAlgorithm> ID_MAP =
            new HashMap<String, EBulkCipherAlgorithm>();

    static {
        String name;
        for (EBulkCipherAlgorithm tmp : EBulkCipherAlgorithm.values()) {
            name = tmp.getName();
            ID_MAP.put(name, tmp);
        }
    }

    /**
     * Set bulk cipher name.
     * @param cipherName Bulk cipher name
     */
    EBulkCipherAlgorithm(final String cipherName) {
        this.name = cipherName;
    }

    /**
     * Get the name of the bulk cipher.
     * @return Bulk cipher name
     */
    public String getName() {
        return this.name;
    }

    /**
     * Get the bulk cipher.
     * @param bulkName Name of the bulk cipher
     * @return Bulk cipher
     */
    public EBulkCipherAlgorithm getBulkCipher(final String bulkName) {
        return ID_MAP.get(bulkName);
    }
}
