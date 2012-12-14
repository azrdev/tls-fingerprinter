/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ssl.analyzer.attacks.bleichenbacher.oracles;

import de.rub.nds.ssl.analyzer.attacks.bleichenbacher.exceptions.OracleException;
import java.net.SocketException;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class TimingOracle extends ATimingOracle {

    /**
     * Constructor
     *
     * @param serverAddress
     * @param serverPort
     * @throws SocketException
     */
    public TimingOracle(final String serverAddress, final int serverPort)
            throws SocketException {
        super(serverAddress, serverPort);
    }

    @Override
    public void trainOracle(byte[] firstRequest, byte[] secondRequest)
            throws OracleException {

        long delay;

        // train the oracle using the executeWorkflow functionality

        for (int i = 0; i < 10; i++) {
            exectuteWorkflow(firstRequest);
            delay = getTimeDelay(getWorkflow().getTraceList());
            System.out.println("delay 1: " + delay);

            exectuteWorkflow(secondRequest);
            delay = getTimeDelay(getWorkflow().getTraceList());
            System.out.println("delay 2: " + delay);
        }
        

        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean checkPKCSConformity(byte[] msg) throws OracleException {

        exectuteWorkflow(msg);
        long delay = getTimeDelay(getWorkflow().getTraceList());

        // analyze delay

        throw new UnsupportedOperationException("Not supported yet.");
    }
}
