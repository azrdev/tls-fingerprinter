package de.rub.nds.virtualnetworklayer.p0f.signature;

import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import de.rub.nds.virtualnetworklayer.p0f.Module;
import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.Option;
import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.Quirk;
import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.TimeToLive;
import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.WindowSize;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.util.Util;

import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;

/**
 * Property format: ver:ittl:olen:mss:wsize,windowScale:olayout:quirks:pclass
 *
 * @see de.rub.nds.virtualnetworklayer.util.IniTokenizer.Property
 * @see Version
 * @see WindowSize
 * @see de.rub.nds.virtualnetworklayer.p0f.signature.tcp.Option
 * @see Quirk
 * @see PayloadClass
 */
public class TCPSignature extends Fingerprint.Signature {

    public enum Version {
        Ip4('4'), Ip6('6'), Any('*');
        private char c;

        private Version(char c) {
            this.c = c;
        }

        private int getInteger() {
            return Character.getNumericValue(c);
        }

        @Override
        public String toString() {
            return String.valueOf(c);
        }
    }

    public enum PayloadClass {
        Any('*'), Zero('0'), Positive('+');
        private char c;

        private PayloadClass(char c) {
            this.c = c;
        }

        @Override
        public String toString() {
            return String.valueOf(c);
        }
    }

    private List<TcpHeader.Option> optionsLayout;

    private void readFromString(String value) {
        String[] parts = value.split(SIGN_DELIMITER);

        Version version = Util.readEnum(Version.class, parts[0]);
        if (version != Version.Any) {
            addSign("version", version.getInteger());
        }

        addSign("timeToLive", new TimeToLive(parts[1]));
        addSign("optionsLength", Util.readBoundedInteger(parts[2], 0, 255));

        if (parts[3].charAt(0) != '*') {
            addSign("maximumSegmentSize", Util.readBoundedInteger(parts[3], 0, 65535));
        }

        readWindow(parts[4]);
        readOptions(parts[5]);
        readQuirks(parts[6]);

        PayloadClass payloadClass = Util.readEnum(PayloadClass.class, parts[7]);
        if (payloadClass != PayloadClass.Any) {
            addSign("payloadClass", payloadClass);
        }
    }

    public TCPSignature(String value) {
        readFromString(value);
    }

    public TCPSignature(String value, Module.Direction direction) {
        readFromString(value);
        addSign("direction", direction.getMapping());
    }

    private void readOptions(String options) {
        optionsLayout = new LinkedList<>();

        String[] parts = options.split(PART_DELIMITER);
        for (String part : parts) {
            optionsLayout.add(Option.read(part).getMapping());
        }

        this.addSign("optionsLayout", optionsLayout);
    }

    private void readQuirks(String value) {
        for (String part : value.split(PART_DELIMITER)) {
            if (!value.isEmpty()) {
                addQuirk(Util.readEnum(Quirk.class, part));
            }
        }
    }

    private void readWindow(String value) {
        String[] parts = value.split(PART_DELIMITER);

        WindowSize windowSize = WindowSize.read(parts[0]);
        if (windowSize.getType() != WindowSize.Type.Any) {
            addSign("windowSize", windowSize);
        }

        if (!parts[1].equals("*")) {
            addSign("windowScale", Util.readBoundedInteger(parts[1], 0, 255));
        }
    }

    @Override
    public int hashCode() {
        return Util.enumHashCode(optionsLayout);
    }

    private static final String SIGN_DELIMITER = ":";
    private static final String PART_DELIMITER = ",";

    public static String writeToString(Fingerprint.Signature signature) {
        StringBuilder sb = new StringBuilder();

        Integer version = signature.getSign("version");
        sb.append((version == null)?  Version.Any : version);
        sb.append(SIGN_DELIMITER);

        TimeToLive ttl = signature.getSign("timeToLive");
        if(ttl != null) sb.append(ttl.getInitialTTL());
        sb.append(SIGN_DELIMITER);

        Integer ol = signature.getSign("optionsLength");
        sb.append((ol == null)? 0 : ol);
        sb.append(SIGN_DELIMITER);

        Integer mss = signature.getSign("maximumSegmentSize");
        sb.append((mss == null)? '*' : mss);
        sb.append(SIGN_DELIMITER);

        WindowSize windowSize = signature.getSign("windowSize");
        sb.append((windowSize == null)? '*' : windowSize);
        sb.append(PART_DELIMITER);
        Integer windowScale = signature.getSign("windowScale");
        sb.append((windowScale == null)? '*' : windowScale);
        sb.append(SIGN_DELIMITER);

        List<TcpHeader.Option> optionsLayout = signature.getSign("optionsLayout");
        if(optionsLayout != null) {
            boolean hasOption = false;
            for(TcpHeader.Option opt : optionsLayout) {
                Option p0fOption = Option.getMapping(opt);
                if(p0fOption != null) {
                    sb.append(p0fOption);
                    sb.append(PART_DELIMITER);
                    hasOption = true;
                }
            }
            //delete last PART_DELIMITER
            if(hasOption)
                sb.setLength(sb.length() - PART_DELIMITER.length());
        }
        sb.append(SIGN_DELIMITER);

        EnumSet<Quirk> quirks = signature.getQuirks();
        if(quirks != null) {
            boolean hasQuirk = false;
            for(Quirk quirk : quirks) {
                sb.append(quirk.toString()).append(PART_DELIMITER);
                hasQuirk = true;
            }
            //delete last PART_DELIMITER
            if(hasQuirk)
                sb.setLength(sb.length() - PART_DELIMITER.length());
        }
        sb.append(SIGN_DELIMITER);

        PayloadClass pc = signature.getSign("payloadClass");
        sb.append((pc == null)? '*' : pc.toString());

        return sb.toString();
    }
}
