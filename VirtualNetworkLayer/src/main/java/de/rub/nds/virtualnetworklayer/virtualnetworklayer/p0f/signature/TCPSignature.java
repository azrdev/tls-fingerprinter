package de.rub.nds.virtualnetworklayer.p0f.signature;

import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import de.rub.nds.virtualnetworklayer.p0f.Module;
import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.Option;
import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.Quirk;
import de.rub.nds.virtualnetworklayer.p0f.signature.tcp.WindowSize;
import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.util.Util;

import java.util.LinkedList;
import java.util.List;

/**
 * Property format: ver:ittl:olen:mss:wsize,windowScale:olayout:quirks:pclass
 *
 * @see de.rub.nds.virtualnetworklayer.util.IniTokenizer.Property
 * @see Version
 * @see WindowSize
 * @see Option
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

    public TCPSignature(String value, Module.Direction direction) {
        String[] parts = value.split(":");

        Version version = Util.readEnum(Version.class, parts[0]);
        if (version != Version.Any) {
            addSign("version", version);
        }

        readInitalTTL(parts[1]);
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

        addSign("direction", direction.getMapping());
    }

    private void readInitalTTL(String initialTTL) {
        if (initialTTL.endsWith("-")) {
            initialTTL = initialTTL.replace("-", "");

        } else if (initialTTL.contains("+")) {
            String[] parts = initialTTL.split("+");
            initialTTL = parts[0];
        }

        this.addSign("timeToLive", Util.readBoundedInteger(initialTTL, 1, 255));
    }

    private void readOptions(String options) {
        optionsLayout = new LinkedList<TcpHeader.Option>();

        String[] parts = options.split(",");
        for (String part : parts) {
            optionsLayout.add(Option.read(part).getMapping());
        }

        this.addSign("optionsLayout", optionsLayout);
    }

    private void readQuirks(String value) {
        for (String part : value.split(",")) {
            if (!value.isEmpty()) {
                addQuirk(Util.readEnum(Quirk.class, part));
            }
        }
    }

    private void readWindow(String value) {
        String[] parts = value.split(",");

        WindowSize windowSize = WindowSize.read(parts[0]);
        if (windowSize != WindowSize.Any) {
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
}
