package de.rub.nds.ssl.stack;

import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECPoint;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECPointFormat;

/**
 * Helpful routines when working with elliptic curves.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Aug 12, 2013
 */
public final class ECUtility {

    /**
     * Utility class only.
     */
    private ECUtility() {
    }

    public static byte[] encodeX9_62(final byte[] x, final byte[] y,
            final EECPointFormat pointFormat) {
        byte[] result;
        switch (pointFormat) {
            case ANSI_X962_COMPRESSED_CHAR2:
                // strip of Y coordinate
                result = new byte[x.length + 1];
                if ((y[0] & (0x01)) == 1) {
                    result[0] = 0x03;
                } else {
                    result[0] = 0x02;
                }
                System.arraycopy(x, 0, result, 1, x.length);
                // TODO check this code for correctness in this case
                break;
            case ANSI_X962_COMPRESSED_PRIME:
                // strip of Y coordinate
                result = new byte[x.length + 1];
                if ((y[0] & (0x01)) == 1) {
                    result[0] = 0x03;
                } else {
                    result[0] = 0x02;
                }
                System.arraycopy(x, 0, result, 1, x.length);
                break;
            case UNCOMPRESSED:
                result = new byte[x.length + y.length + 1];
                result[0] = 0x04;
                System.arraycopy(x, 0, result, 1, x.length);
                System.arraycopy(x, 0, result, 1 + x.length, y.length);
                break;
            default:
                result = new byte[0];
                break;
        }

        return result;
    }
}
