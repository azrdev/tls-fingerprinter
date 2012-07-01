package de.rub.nds.virtualnetworklayer.packet.header.transport;

/**
 * A {@link de.rub.nds.virtualnetworklayer.packet.header.Header} class implements the Port interface to indicate that it
 * contains a {destination, source}Port.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public interface Port {

    int getDestinationPort();

    int getSourcePort();
}
