/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.analyzer.attacks.bleichenbacher.oracles;

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
    boolean checkDecryptedBytes(byte[] msg) {

        boolean conform = false;

        if (msg[0] == 0x00) {
            byte[] tmp = new byte[msg.length - 1];
            System.arraycopy(msg, 1, tmp, 0, tmp.length);
            msg = tmp;
        }

        if (msg[0] == 0x02 && msg.length == (blockSize - 1)) {

            switch (oracleType) {
                case TTT:
                    conform = true;
                    break;

                case FTT:
                    if (checkFirst(msg)) {
                        conform = true;
                    }
                    break;

                case TFT:
                    if (checkSecond(msg)) {
                        conform = true;
                    }
                    break;

                case FFT:
                    if (checkFirst(msg) && checkSecond(msg)) {
                        conform = true;
                    }
                    break;

                case FFF:
                    if (checkFirst(msg) && checkSecond(msg) && checkThird(msg)) {
                        conform = true;
                    }
                    break;

                case JSSE:
                    if (checkJSSE(msg)) {
                        conform = true;
                    }
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
        for (int i = 9; i < blockSize - 1; i++) {
            if (msg[i] == 0x00) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns true if and only if the message contains no 0x00 byte in the
     * first 8 bytes of the decrypted text
     *
     * @param msg
     * @return
     */
    private boolean checkSecond(byte[] msg) {
        for (int i = 1; i < 9; i++) {
            if (msg[i] == 0x00) {
                return false;
            }
        }
        return true;
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
        if (msg[blockSize - 1 - 16] == 0x00) {
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * JSSE bug Plaintext oracle, for testing purposes:
     * 
     * Example for 256 byte long RSA key:
     * The oracle returns true if:
     * <ul>
     *   <li>first 8 bytes are not 0x00</li>
     *   <li>the following 117 bytes contain at least one 0x00 byte</li>
     * </ul>
     * 
     * @param msg
     * @return 
     */
    private boolean checkJSSE(byte[] msg) {
        if(msg.length <= 128) {
            throw new UnsupportedOperationException("The oracle not supported for"
                    + "keys < 1024 bits.");
        }
        // check first 8 bytes
        if(! checkSecond(msg)) {
            return false;
        }
        // check the following bytes (excluding the last PMS and 80 padding bytes)
        int last = msg.length - 49 - 80;
        for (int i=9; i< last; i++) {
            if (msg[i] == 0x00) {
                return true;
            }
        }
        return false;
    }
}
