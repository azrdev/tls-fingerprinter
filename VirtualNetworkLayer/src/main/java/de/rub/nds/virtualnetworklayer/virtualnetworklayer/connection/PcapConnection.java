package de.rub.nds.virtualnetworklayer.connection;

import de.rub.nds.virtualnetworklayer.p0f.Label;
import de.rub.nds.virtualnetworklayer.packet.Packet;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public class PcapConnection implements Connection {
    private PcapTrace trace = new PcapTrace();
    private List<Label> labels = new LinkedList<Label>();

    public PcapConnection(String address, int port) throws IOException {

    }

    public PcapConnection() {

    }

    public Packet read(int timeout) throws IOException {
        throw new IOException();
    }

    public void write(byte[] data) throws IOException {
        throw new IOException();
    }

    public void addLabel(Label label) {
        labels.add(label);
    }

    public PcapTrace getTrace() {
        return trace;
    }

    //TODO
    public List<Label> getLabels(Packet.Direction direction) {
        return labels;
    }
}
