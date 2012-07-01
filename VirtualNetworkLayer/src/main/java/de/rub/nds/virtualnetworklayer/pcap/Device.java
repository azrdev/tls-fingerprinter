package de.rub.nds.virtualnetworklayer.pcap;

import de.rub.nds.virtualnetworklayer.packet.header.link.family.Family;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_addr;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_if;
import de.rub.nds.virtualnetworklayer.pcap.structs.sockaddr;
import org.bridj.Pointer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static de.rub.nds.virtualnetworklayer.packet.header.link.family.Family.AddressFamily;

/**
 * This class represent a network device (respectively interface)
 * reported by pcap.
 * </p>
 * Addresses are sliced to actual length by looking up {@link AddressFamily}.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see Family
 */
public class Device {
    private String description = "";
    private List<byte[]> addresses = new ArrayList<byte[]>();
    private String name;

    public Device(pcap_if pcap_if, int net, int mask) {
        name = pcap_if.name().getCString();

        if (pcap_if.description() != Pointer.NULL) {
            description = pcap_if.description().getCString();
        }


        Pointer<pcap_addr> address = pcap_if.addresses();
        while (address != Pointer.NULL) {
            Pointer<sockaddr> addr = address.get().addr();
            int sa_family = addr.get().sa_family();
            AddressFamily family = AddressFamily.valueOf(sa_family);

            byte[] sa_data = addr.get().sa_data().getBytes(4);

            if (family == AddressFamily.INET6) {
                sa_data = addr.get().sa_data().getBytes();
            }

            addresses.add(sa_data);

            address = address.get().next();
        }
    }

    public String getDescription() {
        return description;
    }

    public List<byte[]> getAddresses() {
        return addresses;
    }

    public boolean isBound(byte[] to) {
        for (byte[] address : getAddresses()) {
            if (Arrays.equals(to, address)) {
                return true;
            }
        }

        return false;
    }

    public String getName() {
        return name;
    }
}
