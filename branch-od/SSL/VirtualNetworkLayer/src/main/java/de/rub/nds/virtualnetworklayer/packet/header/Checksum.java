package de.rub.nds.virtualnetworklayer.packet.header;

/**
 * A {@link Header} class implements the Checksum interface to checksum capabilities.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see Header
 */
public interface Checksum {

    public byte[] getChecksum();

    public byte[] getCalcuatedChecksum();
}
