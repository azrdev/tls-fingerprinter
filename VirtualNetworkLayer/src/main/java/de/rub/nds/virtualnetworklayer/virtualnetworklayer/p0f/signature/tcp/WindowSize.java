package de.rub.nds.virtualnetworklayer.p0f.signature.tcp;

import de.rub.nds.virtualnetworklayer.util.Util;

/**
 * WindowSize with @Deprecated are not used in p0f.fp but in c code
 * (not used any more or not yet)
 */
public enum WindowSize {
    Any("*"),
    Mss("mss", "*", 1, 1000),
    Mtu("mtu", "*", 1, 1000),
    Normal("", "", 0, 65535),

    @Deprecated
    Mod("%", "%", 2, 65535);

    private String value;
    private String separator = "";
    private int rangeBegin;
    private int rangeEnd = 0;

    private int size;

    private WindowSize(String value) {
        this.value = value;
    }

    private WindowSize(String value, String separator) {
        this.separator = separator;
        this.value = value;
    }

    private WindowSize(String value, String separator, int rangeBegin, int rangeEnd) {
        this(value, separator);

        this.rangeBegin = rangeBegin;
        this.rangeEnd = rangeEnd;
    }

    public static WindowSize read(String value) {
        for (WindowSize windowSize : WindowSize.values()) {
            if (value.startsWith(windowSize.value) && !windowSize.value.isEmpty()) {
                if (!windowSize.separator.isEmpty()) {
                    String[] parts = value.split('\\' + windowSize.separator);
                    windowSize.size = Util.readBoundedInteger(parts[1], windowSize.rangeBegin, windowSize.rangeEnd);
                }

                return windowSize;
            }
        }

        return Normal.setSize(Util.readBoundedInteger(value, Normal.rangeBegin, Normal.rangeEnd));
    }

    public WindowSize setSize(int size) {
        this.size = size;
        return this;
    }


    @Override
    public String toString() {
        return value + separator + size;
    }

}
