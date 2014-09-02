package de.rub.nds.virtualnetworklayer.p0f.signature;

import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import de.rub.nds.virtualnetworklayer.util.Util;

/**
 * Property format: mtu
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see de.rub.nds.virtualnetworklayer.util.IniTokenizer.Token.Property
 */
public class MTUSignature extends Fingerprint.Signature {

    public MTUSignature(String value) {
        addSign("mtu", Util.readBoundedInteger(value.trim(), 0, 65535));
    }

    public static String writeToString(Fingerprint.Signature signature) {
        Integer mtu = signature.getSign("mtu");
        if(mtu != null)
            return mtu.toString();

        return "";
    }
}