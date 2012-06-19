package de.rub.nds.virtualnetworklayer.p0f;


import de.rub.nds.virtualnetworklayer.util.Util;

/**
 * Property format: type:class:name:flavor
 *
 * @see de.rub.nds.virtualnetworklayer.util.IniTokenizer.Property
 */
public class Label {
    public enum Type {
        Specific('s'), Generic('g');
        private char c;

        private Type(char c) {
            this.c = c;
        }

        @Override
        public String toString() {
            return String.valueOf(c);
        }
    }

    private Type type;
    private String labelClass;
    private String name = "";
    private String flavor;

    public Label(String value) {
        String[] parts = value.split(":");

        if (parts.length == 1) {
            flavor = value;
            type = Type.Specific;

        } else {
            type = Util.readEnum(Type.class, parts[0]);
            labelClass = parts[1];
            name = parts[2];
            if (parts.length == 4) {
                flavor = parts[3];
            }
        }
    }

    public Type getType() {
        return type;
    }

    public String getLabelClass() {
        return labelClass;
    }

    public String getName() {
        return name;
    }

    public String getFlavor() {
        return flavor;
    }

    public boolean isOSSpecific() {
        return labelClass != null && !labelClass.equals("!");
    }

    @Override
    public String toString() {
        if (name.isEmpty()) {
            return flavor;
        } else {
            return type + ":" + labelClass + ":" + name + ":" + flavor;
        }
    }
}
