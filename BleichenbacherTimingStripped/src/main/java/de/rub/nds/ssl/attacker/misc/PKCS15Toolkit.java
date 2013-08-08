package de.rub.nds.ssl.attacker.misc;

import de.rub.nds.ssl.attacker.bleichenbacher.OracleType;
import static de.rub.nds.ssl.attacker.bleichenbacher.OracleType.FFF;
import static de.rub.nds.ssl.attacker.bleichenbacher.OracleType.FFT;
import static de.rub.nds.ssl.attacker.bleichenbacher.OracleType.FTT;
import static de.rub.nds.ssl.attacker.bleichenbacher.OracleType.TFT;
import static de.rub.nds.ssl.attacker.bleichenbacher.OracleType.TTT;
import static de.rub.nds.ssl.attacker.misc.PKCS15Toolkit.containsByte;
import static de.rub.nds.ssl.attacker.misc.PKCS15Toolkit.hasCorrectKeySize;

/**
 * Helpful routines for PKCS v1.5 handling.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jun 28, 2013
 */
public class PKCS15Toolkit {
/**
     * Checks for PKCS#1 conformity.
     *
     * @param decryptedPKCS PMS to be checked.
     * @param oracleType Type of the oracle.
     * @return True if PKCS#1 conform, false otherwise.
     */
    public static boolean conformityChecker(final byte[] decryptedPKCS,
            final OracleType oracleType, final int blockSize) {
        boolean conform = false;
        byte[] tmpMsg = decryptedPKCS;
        
        if (tmpMsg[0] == 0x00) {
            byte[] tmp = new byte[tmpMsg.length - 1];
            System.arraycopy(tmpMsg, 1, tmp, 0, tmp.length);
            tmpMsg = tmp;
        }
        
        if (tmpMsg[0] == 0x02 && tmpMsg.length == (blockSize-1)) {
            System.out.println("    CASE X starting with 00 02");
            switch (oracleType) {
                case TTT:
                    conform = true;
                    break;

                case FTT:
                    if (checkFirst(tmpMsg, blockSize)) {
                        conform = true;
                    }
                    break;

                case TFT:
                    if (checkSecond(tmpMsg)) {
                        conform = true;
                    }
                    break;

                case FFT:
                    if (checkFirst(tmpMsg, blockSize) && checkSecond(tmpMsg)) {
                        System.out.println("    CASE 2 with 00 02, 00 on valid position");
                        conform = true;
                    }
                    break;

                case FFF:
                    if (checkFirst(tmpMsg, blockSize) && checkSecond(tmpMsg)
                            && checkThird(tmpMsg)) {
                        conform = true;
                    }
                    break;

                default:
                    break;
            }
        } else {
            System.out.println("    CASE 3 with 00 " + tmpMsg[0]);
        }

        return conform;
    }

    /**
     * Returns true if and only if the message contains a 0x00 byte in the
     * decrypted text (except of the first 8 bytes)
     *
     * @param msg
     * @return
     */
    private static boolean checkFirst(final byte[] msg, final int blockSize) {
        boolean result = false;
        for (int i = 9; i < blockSize-1 && !result; i++) {
            if (msg[i] == 0x00) {
                result = true;
            }
        }

        return result;
    }

    /**
     * Returns true if and only if the message contains no 0x00 byte in the
     * first 8 bytes of the decrypted text
     *
     * @param msg
     * @return
     */
    private static boolean checkSecond(final byte[] msg) {
        boolean result = true;
        for (int i = 1; i < 9; i++) {
            if (msg[i] == 0x00) {
                result = false;
            }
        }
        return result;
    }

    /**
     * Returns true if and only if the message contains the 0x00 byte on the
     * correct position in the plaintext.
     *
     * @param msg
     * @return
     */
    private static boolean checkThird(final byte[] msg) {
        boolean result = false;
        if (hasCorrectKeySize(48, msg)) {
            result = true;
        }
        return result;
    }

    /**
     * checks if the message contains byte b in the area between <from,to>
     *
     * @param b
     * @param msg
     * @param from
     * @param to
     * @return
     */
    public static boolean containsByte(final byte b, final byte[] msg,
            final int from, final int to) {
        boolean result = false;
        for (int i = from; i < to; i++) {
            if (msg[i] == b) {
                result = true;
                break;
            }
        }
        return result;
    }

    /**
     * Checks, if 0x00 is defined on a good position and if before this 0x00
     * byte is no other 0x00
     *
     * @param keySize the length of the key included in the PKCS1 message
     * @param msg message
     * @return
     */
    public static boolean hasCorrectKeySize(final int keySize, final byte[] msg) {
        boolean result = false;
        // check if the second last byte is equal to 0x00
        if (msg[msg.length - keySize - 1] == 0x00) {
            /* 
             * Starts from 10 because the first 8 bytes are checked by 
             * checkSecond and the first 2 bytes are the PKCS type
             * (covered by implicit check of checkDecryptedBytes)
             */
            if (!containsByte((byte) 0x00, msg, 10, msg.length - keySize - 1)) {
                result = true;
            }
        }
        return result;
    }
}
