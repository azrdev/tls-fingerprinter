package de.rub.nds.ssl.attacker.bleichenbacher;

/**
 * <DESCRIPTION>
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jun 27, 2013
 */
public enum OracleType {
    /**
     * Oracle types defined in the Crypto'12 paper + specific oracles found
     * during our research
     *
     * TTT checks only 0x00 0x02 ...
     *
     * FFF checks 0x00 0x02 on the beginning, the first 8 bytes cannot include
     * 0x00 and the 0x00 byte has to be set on a correct position
     */
    TTT, TFT, FTT, FFT, FFF
}
