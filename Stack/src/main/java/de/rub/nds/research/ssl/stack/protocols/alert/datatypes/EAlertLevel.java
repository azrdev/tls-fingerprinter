package de.rub.nds.research.ssl.stack.protocols.alert.datatypes;

import java.util.HashMap;
import java.util.Map;

/**
 * Alert levels of an Alert message
 *
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 *
 * Apr. 08, 2012
 */
public enum EAlertLevel {

    WARNING((byte) 0x01),
    FATAL((byte) 0x02);
    private byte level;
    final private static Map<Integer, EAlertLevel> ID_MAP = 
            new HashMap<Integer, EAlertLevel>();

    static {
        byte id;
        for (EAlertLevel tmp : EAlertLevel.values()) {
            id = tmp.getAlertLevelId();
            ID_MAP.put((int) id, tmp);
        }
    }

    EAlertLevel(byte level) {
        this.level = level;
    }

    /**
     * Get the byte-value of the alert level
     *
     * @return byte-value of the alert level
     */
    public byte getAlertLevelId() {
        return this.level;
    }

    /**
     * Get the alert level
     *
     * @param level byte-value of the alert level
     * @return alert level of the alert message
     */
    public static EAlertLevel getAlertLevel(byte level) {
        return ID_MAP.get((int) level);
    }
}
