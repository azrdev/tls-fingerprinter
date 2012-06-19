package de.rub.nds.virtualnetworklayer.pcap;

import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_addr;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_if;
import de.rub.nds.virtualnetworklayer.pcap.structs.sockaddr;
import de.rub.nds.virtualnetworklayer.util.Util;
import org.bridj.Pointer;

import java.util.ArrayList;
import java.util.List;

public class Device {
    private String description = "";
    private List<byte[]> addresses = new ArrayList<byte[]>();
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
            addresses.add(sa_data);

            address = address.get().next;
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
            if (Util.toIp4String(to).equals(Util.toIp4String(address))) {
                return true;
            }
        }

        return false;
    }

    public String getName() {
        return name;
    }
}
