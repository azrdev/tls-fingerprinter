package de.rub.nds.virtualnetworklayer.pcap;

import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_addr;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_if;
import de.rub.nds.virtualnetworklayer.pcap.structs.sockaddr;
import org.bridj.Pointer;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public class Device {
    private String description = "";
    private List<InetAddress> addresses = new ArrayList<InetAddress>();
    private String name;

    public Device(pcap_if pcap_if, int net, int mask) {
        name = pcap_if.name.getCString();

        if (pcap_if.description != Pointer.NULL) {
            description = pcap_if.description.getCString();
        }


        Pointer<pcap_addr> address = pcap_if.addresses;

        while (address != Pointer.NULL) {
            Pointer<sockaddr> addr = address.get().addr;
            int sa_family = addr.get().sa_family;
            byte[] sa_data = addr.get().sa_data.getBytes();

            try {
                addresses.add(InetAddress.getByAddress(sa_data));
            } catch (UnknownHostException e) {

            }

            address = address.get().next;
        }
    }

    public String getDescription() {
        return description;
    }

    public List<InetAddress> getAddresses() {
        return addresses;
    }

    public String getName() {
        return name;
    }
}
