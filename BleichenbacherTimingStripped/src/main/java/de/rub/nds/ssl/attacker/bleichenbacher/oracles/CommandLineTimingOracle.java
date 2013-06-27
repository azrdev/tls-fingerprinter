package de.rub.nds.ssl.attacker.bleichenbacher.oracles;

import de.rub.nds.ssl.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.attacker.bleichenbacher.OracleType;
import de.rub.nds.ssl.attacker.misc.CommandLineWorkflowExecutor;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Stripped down version of the Timing Oracle.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jun 27, 2013
 */
public class CommandLineTimingOracle extends AOracle {

    /*
     * CONFIGURATION SECTION
     */
    /**
     * Amount of training measurementsTest.
     */
    private static final int TRAINING_AMOUNT = 1000;
    /**
     * Amount of warmup measurementsTest.
     */
    private static final int WARMUP_AMOUNT = 50;
    /**
     * Timing difference between invalid and valid timings.
     */
    private static final long VALID_INVALID_BOUNDARY = -20000;
    /**
     * Amount of measurementsTest per Oracle query.
     */
    private static final int MEASUREMENT_AMOUNT = 100;
    /**
     * TODO: Sebastian - bitte bitte bitte Parameter kommentieren!
     */
    private static final int MEASUREMENT_FACTOR_FOR_VALIDITY = 1;
    /*
     * RUNTIME DATA SECTION
     */
    /**
     * Bridge to the executing client.
     */
    private CommandLineWorkflowExecutor clwe;
    /**
     * List of valid timings.
     */
    private ArrayList<Long> validTimings = new ArrayList<>(TRAINING_AMOUNT);
    /**
     * List of invalid timings.
     */
    private ArrayList<Long> invalidTimings = new ArrayList<>(TRAINING_AMOUNT);
    /**
     * TODO: Sebastian - bitte bitte bitte Parameter kommentieren!
     */
    private int counterOracle = 0;
    /**
     * RSA private key (needed for the cheat operation)
     */
    private RSAPrivateKey privateKey;
    /**
     * Cipher (needed for the cheat operation)
     */
    private Cipher cipher;

    /**
     * Create a new instance of this object.
     *
     * @param type
     * @param publicKey
     * @param privateKey
     */
    public CommandLineTimingOracle(final OracleType type,
            final RSAPublicKey publicKey, final RSAPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.oracleType = type;
        this.blockSize = computeBlockSize(publicKey);
        try {
            this.cipher = Cipher.getInstance("RSA/None/NoPadding");
            this.cipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            ex.printStackTrace();
        }

        this.clwe = new CommandLineWorkflowExecutor("./client ");
    }

    /**
     * This method performs the statistical analysis of the timing
     * measurementsTest. It assumes that a valid key has a significantly lower
     * response time than an invalid key. In a nutshell, the method performs
     * Crosby's box test.
     *
     * @param testPKCS PKCS to be tested for validity.
     * @return True if the PKCS was a valid one or false otherwise.
     */
    private boolean isValidPKCS(final byte[] testPKCS) {
        boolean result = false;

        // TODO: Sebastian - hier muss der Code rein der valid von invalid 
        // unterscheidet.

        return result;
    }

    /**
     * Train the timing oracle.
     *
     * @param validPMS Valid PMS
     * @param invalidPMS InvalidPMS
     * @throws OracleException
     */
    public void trainOracle(final byte[] validPMS, final byte[] invalidPMS)
            throws OracleException {
        clwe.executeClientWithPMS(validPMS);
        clwe.executeClientWithPMS(invalidPMS);

        // warmup
        System.out.print("warmup... ");
        for (int i = 0; i < WARMUP_AMOUNT / 2; i++) {
            clwe.executeClientWithPMS(validPMS);
            clwe.executeClientWithPMS(invalidPMS);
            System.out.println(i + "th round");
        }
        System.out.println("done!");

        long delay;
        // train the oracle using the executeWorkflow functionality
        for (int i = 0; i < TRAINING_AMOUNT; i++) {
            delay = clwe.executeClientWithPMS(validPMS);
            validTimings.add(delay);

            delay = clwe.executeClientWithPMS(invalidPMS);
            invalidTimings.add(delay);

            System.out.print("\r left requests for training "
                    + (TRAINING_AMOUNT - i));
        }
        System.out.println("\n");
        FileWriter fw = null;
        try {
            fw = new FileWriter("training_data.csv");

            for (int i = 0; i < TRAINING_AMOUNT; i++) {
                fw.write(i + ";invalid;" + invalidTimings.get(i) + "\n");
                fw.write((i + TRAINING_AMOUNT) + ";valid;"
                        + validTimings.get(i) + "\n");
            }
            fw.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    @Override
    public boolean checkPKCSConformity(final byte[] preMasterSecret)
            throws OracleException {
        boolean result = false;
        boolean groundTruth = false;

        counterOracle += 1;

        groundTruth = cheat(preMasterSecret);

        if (counterOracle < 792) {
            if (counterOracle % 100 == 0) {
                System.out.print("\r" + counterOracle);
            }
            if (groundTruth == true) {
                System.out.println(counterOracle + "TRUE!!!");
            }
            return groundTruth;
        }

        boolean test = isValidPKCS(preMasterSecret);

        if (groundTruth == false) {
            if (test == false) {
                /*
                 * all good!
                 */
                result = test;
            } else {
                /*
                 * The submitted key was invalid but our test predicted 
                 * that the key was valid. This is the worst case, because 
                 * it will most certainly break the subsequent computations. 
                 * We will stop here.
                 */
                System.err.println("ERROR: invalid key was predicted to "
                        + "be valid. Stopping.");
                result = test;
            }

        } else {
            if (test == false) {
                /*
                 * The submitted key was valid but our test predicted that 
                 * the key was invalid. This decreases the performance of 
                 * the attack but does not necessarily break subsequent 
                 * computations.
                 */
                System.err.println("ERROR: valid key was predicted to "
                        + "be invalid. This decreases the attack "
                        + "performance.");
                result = test;
            } else {
                /*
                 * all good!
                 */
                result = test;
            }
        }

        System.out.println(counterOracle + ": Ground truth: "
                + groundTruth + ", timingoracle: " + result);

        return result;
    }

    /**
     * Checks for PKCS#1 conformity.
     *
     * @param decryptedPKCS PMS to be checked.
     * @param oracleType Type of the oracle.
     * @return True if PKCS#1 conform, false otherwise.
     */
    private static boolean pkcsConformityChecker(final byte[] decryptedPKCS,
            final OracleType oracleType, final int blockSize) {
        boolean conform = false;
        byte[] tmpMsg = decryptedPKCS;

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
    private static boolean containsByte(final byte b, final byte[] msg,
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
    private static boolean hasCorrectKeySize(final int keySize, final byte[] msg) {
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

    private static int computeBlockSize(final RSAPublicKey publicKey) {
        byte[] tmp = publicKey.getModulus().toByteArray();
        int result = tmp.length;
        int remainder = tmp.length % 8;

        if (remainder > 0 && tmp[0] == 0x0) {
            // extract signing byte if present
            byte[] tmp2 = new byte[tmp.length - 1];
            System.arraycopy(tmp, 1, tmp2, 0, tmp2.length);
            tmp = tmp2;
            remainder = tmp.length % 8;
            result = tmp.length;
        }

        while (remainder > 0) {
            result++;
            remainder = result % 8;
        }

        return result;
    }

    private boolean cheat(final byte[] pms) {
        boolean result = false;
        try {
            byte[] decryptedPMS = cipher.doFinal(pms);
            result = pkcsConformityChecker(decryptedPMS, oracleType, blockSize);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return result;
    }
}
