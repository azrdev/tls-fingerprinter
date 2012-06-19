package de.rub.nds.virtualnetworklayer.p0f.signature.tcp;

import de.rub.nds.virtualnetworklayer.util.Util;

/**
 * WindowSize with @Deprecated are not used in p0f.fp but in c code
 * (not used any more or not yet)
 */
public class WindowSize {

    public static enum Type {
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

        private Type(String value) {
            this.value = value;
        }

        private Type(String value, String separator) {
            this.separator = separator;
            this.value = value;
        }

        private Type(String value, String separator, int rangeBegin, int rangeEnd) {
            this(value, separator);

            this.rangeBegin = rangeBegin;
            this.rangeEnd = rangeEnd;
        }
    }

    private int size;
    private Type type;

    public WindowSize(int size, Type type) {
        this.size = size;
        this.type = type;
    }

    public static WindowSize read(String value) {
        int size = 0;

        for (Type type : WindowSize.Type.values()) {
            if (value.startsWith(type.value) && !type.value.isEmpty()) {
                if (!type.separator.isEmpty()) {
                    String[] parts = value.split('\\' + type.separator);
                    size = Util.readBoundedInteger(parts[1], type.rangeBegin, type.rangeEnd);
                }

                return new WindowSize(size, type);
            }
        }

        return new WindowSize(Util.readBoundedInteger(value, Type.Normal.rangeBegin, Type.Normal.rangeEnd), Type.Normal);
    }

    public Type getType() {
        return type;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof WindowSize)) {
            return false;
        }

        WindowSize other = (WindowSize) o;

        if (size != other.size || type != other.type) {
            return false;
        }

        return true;
    }

    @Override
    public String toString() {
        return type.value + type.separator + size;
    }

}
