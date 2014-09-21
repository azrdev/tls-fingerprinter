package de.rub.nds.ssl.stack.protocols.commons;

import de.rub.nds.ssl.stack.Utility;

import java.util.Arrays;

/**
 * Class to replace byte[] when serialization is needed - use for raw Id fields when the
 * accompanying enum might not exist.
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class Id {
    private final byte[] bytes;

    public Id(byte[] bytes) {
        this.bytes = bytes;
    }

    public Id(byte bytes) {
        this.bytes = new byte[] {bytes};
    }

    public byte[] getBytes() {
        return bytes;
    }

    @Override
    public String toString() {
        return Utility.bytesIdToHex(bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Id id = (Id) o;

        if (!Arrays.equals(bytes, id.bytes)) return false;

        return true;
    }
}
