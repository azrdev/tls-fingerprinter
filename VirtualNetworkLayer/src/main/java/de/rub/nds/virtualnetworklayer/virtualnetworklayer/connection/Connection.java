package de.rub.nds.virtualnetworklayer.connection;

import de.rub.nds.virtualnetworklayer.packet.Packet;

import java.io.IOException;

public interface Connection {

    public static abstract class Trace<T extends Packet> implements Iterable<T> {

        public abstract T get(int position);

        public abstract int size();

    }

    public Packet read(int timeout) throws IOException;

    public void write(byte[] data) throws IOException;

    public Trace getTrace();
}
