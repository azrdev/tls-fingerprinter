package de.rub.nds.ssl.attacker;

import de.rub.nds.ssl.attacker.bleichenbacher.Bleichenbacher;
import de.rub.nds.ssl.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.attacker.bleichenbacher.OracleType;
import de.rub.nds.ssl.attacker.bleichenbacher.oracles.CommandLineTimingOracle;
import de.rub.nds.ssl.attacker.misc.CommandLineWorkflowExecutor;

/**
 * Measurement launcher.
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jun 28, 2013
 */
public class Launcher {
    /**
     * Command to be executed.
     */
//    private static final String COMMAND = "sshpass -p password ssh -t chris@192.168.1.2 '/opt/matrixssl/apps/client '";
    private static final String COMMAND = "../matrixssl/apps/client ";
    
        /**
     * Main entry point.
     * @param args Arguments will be ignored
     * @throws OracleException 
     */
    public static void main(final String[] args) throws OracleException  {
        // just for testing
        CommandLineWorkflowExecutor executor = 
                new CommandLineWorkflowExecutor(COMMAND);
        executor.executeClientWithPMS("aaa=".getBytes());
        
//        CommandLineTimingOracle oracle = new CommandLineTimingOracle(
//                OracleType.TTT, publicKey, privateKey);
//        Bleichenbacher attack = new Bleichenbacher(conformPKCSMessage, oracle,
//                true);
//        attack.attack();
    }
}
