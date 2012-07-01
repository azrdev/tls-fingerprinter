package de.rub.nds.virtualnetworklayer.packet.header.application;

import de.rub.nds.virtualnetworklayer.packet.Headers;
import de.rub.nds.virtualnetworklayer.packet.header.Header;
import de.rub.nds.virtualnetworklayer.packet.header.transport.UdpHeader;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import de.rub.nds.virtualnetworklayer.util.formatter.Format;
import de.rub.nds.virtualnetworklayer.util.formatter.IpFormatter;
import de.rub.nds.virtualnetworklayer.util.formatter.MacFormatter;
import de.rub.nds.virtualnetworklayer.util.formatter.Protocol;

import java.util.LinkedList;
import java.util.List;

/**
 * Dynamic Host Configuration Protocol
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
@Protocol(layer = Protocol.Osi.Application)
public class DhcpHeader extends Header {
    public final static int Id = Headers.Dhcp.getId();

    public static enum MessageType {
        Discover,
        Offer,
        Request,
        Decline,
        Acknowledgment,
        NegativeAcknowledgment,
        Release,
        Informational
    }

    public MessageType getMessageType() {
        return MessageType.values()[getUByte(0) - 1];
    }

    public int getHardwareType() {
        return getUByte(1);
    }

    public int getHardwareAddressLength() {
        return getUByte(2);
    }

    public int getHops() {
        return getUByte(3);
    }

    public int getTransactionId() {
        return getInteger(4);
    }

    public int getSecondsElapsed() {
        return getUShort(8);
    }

    public int getFlags() {
        return getUShort(10);
    }

    @Format(with = IpFormatter.class)
    public byte[] getClientIpAddress() {
        return getBytes(12, 4);
    }


    @Format(with = IpFormatter.class)
    public byte[] getYourIpAddress() {
        return getBytes(16, 4);
    }

    @Format(with = IpFormatter.class)
    public byte[] getServerIpAddress() {
        return getBytes(20, 4);
    }

    @Format(with = IpFormatter.class)
    public byte[] getGatewayIpAddress() {
        return getBytes(24, 4);
    }

    @Format(with = MacFormatter.class)
    public byte[] getClientHardwareAddress() {
        return getBytes(28, getHardwareAddressLength());
    }

    public String getServerHostName() {
        return new String(getBytes(44, 64)).trim();
    }

    public String getBootFileName() {
        return new String(getBytes(108, 128)).trim();
    }

    public List<Option<Integer>> getOptions() {
        LinkedList<Option<Integer>> options = new LinkedList<Option<Integer>>();

        int i = 240;
        int id;

        while (i < getLength() && (id = getUByte(i)) != 0xFF) {
            int length = getUByte(i + 1);
            byte[] data = getBytes(i + 2, length);

            Option option = new Option<Integer>(id, length, data);
            options.add(option);

            i += length + 2;
        }

        return options;
    }

    @Override
    public int getLength() {
        return getBufferLength();
    }

    @Override
    public int getId() {
        return Id;
    }

    @Override
    public boolean isBound(LinkedList<Header> previousHeaders, Pcap.DataLinkType dataLinkType) {
        if (previousHeaders.getLast() instanceof UdpHeader) {
            UdpHeader udpHeader = (UdpHeader) previousHeaders.getLast();

            return udpHeader.getSourcePort() == 67 || udpHeader.getSourcePort() == 68;
        }

        return false;
    }
}
