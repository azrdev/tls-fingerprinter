package de.rub.nds.virtualnetworklayer.packet.header.application;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.Port;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

/**
 * Session Initiation Protocol
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.Application)
public class SipHeader extends HttpHeader {
    public final static int Id = Headers.Sip.getId();
    public final static Set<String> Requests;

    static {
        Requests = new HashSet<String>();
        Requests.add("INVITE");
        Requests.add("ACK");
        Requests.add("BYE");
        Requests.add("CANCEL");
        Requests.add("OPTIONS");
        Requests.add("REGISTER");
    }

    private boolean bindToDefaultPorts;

    public SipHeader(boolean bindToDefaultPorts, boolean bindToDefaultPorts1) {
        this(true);
    }

    public SipHeader(boolean bindToDefaultPorts) {
        this.bindToDefaultPorts = bindToDefaultPorts;
    }

    @Override
    public Packet.Direction getDirection() {
        if (getString(0, 3).equals("SIP")) {
            return Packet.Direction.Response;
        }

        for (String request : Requests) {
            if (getString(0, request.length()).equals(request)) {
                return Packet.Direction.Request;
            }
        }

        return null;
    }


    public int getStatusCode() {
        return Integer.parseInt(getString(8, 3));
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if ((previousHeaders.size() > 0) && (previousHeaders.getLast() instanceof Port)) {
            Port header = (Port) previousHeaders.getLast();

            if (bindToDefaultPorts && !(header.getDestinationPort() == 5060 || header.getSourcePort() == 5060)) {
                return false;
            }

            return getDirection() != null;
        }

        return false;
    }
}
