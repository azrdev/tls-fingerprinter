package de.rub.nds.virtualnetworklayer.p0f.signature;

import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import de.rub.nds.virtualnetworklayer.util.Util;

import java.util.List;

/**
 * Property format: mtu
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see de.rub.nds.virtualnetworklayer.util.IniTokenizer.Token.Property
 */
public class MTUSignature extends Fingerprint.Signature {

    public MTUSignature(final List<String> signs) {
        if(signs.size() > 1)
            throw new IllegalArgumentException("Too many signs: " + signs);
        if(signs.size() > 0)
            readFromString(signs.get(0));
    }

    public MTUSignature(String value) {
        readFromString(value);
    }

    private void readFromString(String value) {
        try {
            addSign("mtu", Util.readBoundedInteger(value.trim(), 0, 65535));
        } catch(NumberFormatException e) {
            // skip addSign
        }
    }

    public static String writeToString(Fingerprint.Signature signature) {
        Integer mtu = signature.getSign("mtu");
        if(mtu != null)
            return mtu.toString();

        return "";
    }
}