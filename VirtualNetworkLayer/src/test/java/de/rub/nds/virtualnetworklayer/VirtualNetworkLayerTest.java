package de.rub.nds.virtualnetworklayer;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        SocketConnectionTest.class,
        PcapTest.class,
        PacketHandlerTest.class,
        ConnectionHandlerTest.class,
        PcapConnectionTest.class
})
public class VirtualNetworkLayerTest {

}
