package de.rub.nds.virtualnetworklayer.p0f.signature.tcp;


import de.rub.nds.virtualnetworklayer.packet.header.transport.TcpHeader;
import de.rub.nds.virtualnetworklayer.util.Util;

/**
 * Options with @Deprecated are not used in p0f.fp but in c code
 * (not used any more or not yet)
 */
public enum Option {
    NOP("nop", TcpHeader.Option.NoOp),
    MAX_SEG("mss", TcpHeader.Option.MaximumSegmentSize),
    WSCALE("ws", TcpHeader.Option.WindowScale),
    SACKOK("sok", TcpHeader.Option.SackPermitted),
    TSTAMP("ts", TcpHeader.Option.TimeStamp),
    EOL("eol", "+", TcpHeader.Option.EndOfOptionsList),
    Any("?", ","),

    @Deprecated
    SACK("sack", TcpHeader.Option.Sack);

    private String value;
    private String separator = "";
    private int number;
    private TcpHeader.Option mapping;

    private Option(String value, TcpHeader.Option mapping) {
        this.value = value;
        this.mapping = mapping;
    }

    private Option(String value, String separator, TcpHeader.Option mapping) {
        this.value = value;
        this.separator = separator;
        this.mapping = mapping;
    }

    private Option(String value, String separator) {
        this(value, separator, null);
    }


    public static Option read(String value) {
        for (Option option : Option.values()) {
            if (value.startsWith(option.value)) {
                if (!option.separator.isEmpty()) {
                    String[] parts = value.split('\\' + option.separator);
                    option.number = Util.readBoundedInteger(parts[1], 0, 255);
                }

                return option;
            }
        }

        return Any;
    }

    public void setNumber(int number) {
        this.number = number;
    }

    @Override
    public String toString() {
        return value + separator + ((number != 0) ? number : "");
    }

    public TcpHeader.Option getMapping() {
        return mapping.setValue(number);
    }
}