package de.rub.nds.virtualnetworklayer.p0f.signature.tcp;

import de.rub.nds.virtualnetworklayer.util.Util;

public class TimeToLive implements Comparable<TimeToLive> {

    private int initialTTL;

    public TimeToLive(String value) {
        if (value.endsWith("-")) {
            value = value.replace("-", "");

        } else if (value.contains("+")) {
            String[] parts = value.split("+");
            value = parts[0];
        }

        initialTTL = Util.readBoundedInteger(value, 1, 255);
    }

    public TimeToLive(int initialTTL) {
        this.initialTTL = initialTTL;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof TimeToLive)) {
            return false;
        }

        TimeToLive other = (TimeToLive) o;

        return initialTTL == other.initialTTL;
    }

    @Override
    public String toString() {
        return String.valueOf(initialTTL);
    }

    @Override
    public int compareTo(TimeToLive other) {
        return other.initialTTL - initialTTL;
    }
}
