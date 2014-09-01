package de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.ECompressionMethod;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Utility to serialize {@link Fingerprint}s.
 *
 * Add all types that may be signs and their serialization type to <code>serializeSign()</code>
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class Serializer {
    /**
     * Build the Serialized form of a sign
     */
    public static String serialize(Object sign) {
        if(sign == null)
            return "";

        //FIXME: better mapping & dispatch of sign-type -> serialization method

        if(sign instanceof Object[])
            return serializeList((Object[]) sign);
        else if(sign instanceof Collection)
            return serializeList((Collection) sign);
        else if(sign instanceof EProtocolVersion)
            return Utility.bytesToHex(((EProtocolVersion) sign).getId(), false);
        else if(sign instanceof ECompressionMethod)
            return Utility.bytesToHex(((ECompressionMethod) sign).getId(), false);
        else if(sign instanceof ECipherSuite)
            return Utility.bytesToHex(((ECipherSuite) sign).getId(), false);
        else if(sign instanceof EExtensionType)
            return Utility.bytesToHex(((EExtensionType) sign).getId(), false);
        else
            return sign.toString();
    }

    private static String serializeList(Collection arr) {
        StringBuilder sb = new StringBuilder();

        for(Object o : arr) {
            // recursive call to serialize that element
            // never put Object[] as sign value, or this will break!
            sb.append(serialize(o)).append(',');
        }
        if(sb.length() > 0)
            // delete trailing ','
            sb.setLength(sb.length() -1);

        return sb.toString();
    }

    private static String serializeList(Object[] arr) {
        return serializeList(Arrays.asList(arr));
    }
}
