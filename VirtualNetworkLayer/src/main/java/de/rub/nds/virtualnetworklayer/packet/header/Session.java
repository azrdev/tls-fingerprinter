package de.rub.nds.virtualnetworklayer.packet.header;

import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import de.rub.nds.virtualnetworklayer.packet.header.transport.SocketSession;

/**
 * A {@link Header} class implements the Session interface to indicate that it has
 * session capabilities (e.g Udp or Tcp).
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see SocketSession
 * @see Header
 */
public interface Session {

    public SocketSession getSession(PcapPacket packet);
}
