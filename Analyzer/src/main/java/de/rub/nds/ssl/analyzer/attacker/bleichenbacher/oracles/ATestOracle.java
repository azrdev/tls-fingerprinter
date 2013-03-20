/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public abstract class ATestOracle extends AOracle {

    /**
     * checks the message and its PKCS#1 conformity according to the oracle type
     *
     * @param msg
     * @return
     */
    boolean checkDecryptedBytes(final byte[] msg) {

        boolean conform = false;
        byte[] tmpMsg = msg;

        if (tmpMsg[0] == 0x00) {
            byte[] tmp = new byte[tmpMsg.length - 1];
            System.arraycopy(tmpMsg, 1, tmp, 0, tmp.length);
            tmpMsg = tmp;
        }

        if (tmpMsg[0] == 0x02 && tmpMsg.length == (blockSize - 1)) {
            switch (oracleType) {
                case TTT:
                    conform = true;
                    break;

                case FTT:
                    if (checkFirst(tmpMsg)) {
                        conform = true;
                    }
                    break;

                case TFT:
                    if (checkSecond(tmpMsg)) {
                        conform = true;
                    }
                    break;

                case FFT:
                    if (checkFirst(tmpMsg) && checkSecond(tmpMsg)) {
                        conform = true;
                    }
                    break;

                case FFF:
                    if (checkFirst(tmpMsg) && checkSecond(tmpMsg)
                            && checkThird(tmpMsg)) {
                        conform = true;
                    }
                    break;

                case JSSE:
                    if (checkJSSE(tmpMsg)) {
                        conform = true;
                    }
                    break;

                case XMLENC:
                    if (checkXMLENC(tmpMsg)) {
                        conform = true;
                    }
                    break;
                default:
                    break;
            }
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
    private boolean checkFirst(byte[] msg) {
        boolean result = false;
        for (int i = 9; i < blockSize - 1; i++) {
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
    private boolean checkSecond(byte[] msg) {
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
     * correct position in the plaintext (e.g. the 16th byte from behind in case
     * of AES128)
     *
     * @param msg
     * @return
     */
    private boolean checkThird(byte[] msg) {
        boolean result = false;
        if (msg[blockSize - 1 - 16] == 0x00) {
            result = true;
        }
        return result;
    }

    /**
     * JSSE bug Plaintext oracle, for testing purposes:
     *
     * Example for 256/512 byte long RSA key: The oracle returns true if: <ul>
     * <li>first two bytes are equal to 0x00 0x02</li> <li>the following 8 bytes
     * do not contain 0x00</li> <li>the following (l-48-80) bytes contain at
     * least one 0x00 byte, where l is the message/key length</li> </ul>
     *
     * @param msg
     * @return
     */
    private boolean checkJSSE(byte[] msg) {
        // check first 8 bytes
        if (!checkSecond(msg)) {
            return false;
        }
        // check if the second last byte is equal to 0x00
        if (msg[msg.length - 2] == 0x00) {
            if (!containsByte((byte) 0x00, msg, 10, msg.length - 2)) {
                return true;
            }
        }

        if (msg.length > 128) {
            // check the following bytes (excluding the last PMS and 80 padding bytes)
            int last = msg.length - 1 - 48 - 80;
            for (int i = 9; i < last; i++) {
                if (msg[i] == 0x00) {
                    // if message contains 0x00 in one of the following bytes, our
                    // oracle returns an Internal error
                    return true;
                }
            }
        }
        // otherwise, no Internal error is returned
        return false;
    }

    /**
     * Presents an XML Encryption oracle. This oracle checks, if the wrapped key
     * has a correct size. It must be either 16, 24, or 32 bytes long.
     *
     * @param msg
     * @return
     */
    private boolean checkXMLENC(byte[] msg) {

        // check first 8 bytes
        if (!checkSecond(msg)) {
            return false;
        }

        if (hasCorrectKeySize(16, msg) || hasCorrectKeySize(24, msg)
                || hasCorrectKeySize(32, msg)) {
            return true;
        }
        return false;
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
    private boolean containsByte(byte b, byte[] msg, int from, int to) {
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
    private boolean hasCorrectKeySize(int keySize, byte[] msg) {
        boolean result = false;
        // check if the second last byte is equal to 0x00
        if (msg[msg.length - keySize] == 0x00) {
            if (!containsByte((byte) 0x00, msg, 10, msg.length - keySize)) {
                result = true;
            }
        }
        return result;
    }
}
