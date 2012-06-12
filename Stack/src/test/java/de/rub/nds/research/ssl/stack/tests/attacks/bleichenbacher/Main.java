package de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher;

import de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher.BleichenbacherAttack;
import de.rub.nds.research.ssl.stack.tests.attacks.bleichenbacher.StandardOracle;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.getInstance;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Bleichenbacher attack launcher.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * May 18, 2012
 */
public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, SSLException {
        byte[] plainBytes = "Decrypt me".getBytes();
        byte[] cipherBytes;

        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        Cipher cipher = getInstance("RSA/None/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        cipherBytes = cipher.doFinal(plainBytes);

        StandardOracle oracle = new StandardOracle(keyPair.getPrivate(), keyPair.getPublic());
        JSSEOracle jsseOracle = new JSSEOracle("www.heise.de", 443);
        System.out.println(jsseOracle.getPublicKey().toString());
        
        BleichenbacherAttack attacker = new BleichenbacherAttack(cipherBytes,
                (RSAPublicKey) keyPair.getPublic(), oracle);

        //attacker.attack();
    }
}
