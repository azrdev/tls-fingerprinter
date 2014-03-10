package de.rub.nds.tinytlssocket;

import java.net.InetAddress;

/**
 * Server launcher.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @author Oliver Domke - oliver.domke@ruhr-uni-bochum.de
 * @version 0.2
 *
 * Feb 05, 2014
 */
public class Launcher {

    /**
     * TinyTLSServer launcher
     *
     * @param args key store path, password, protocol version, port
     */
    public static void main(String[] args) throws Exception {
        //Key store path, Password, Port, Allow unsecure renegotiation
        if(args.length == 4){
            int port = Integer.parseInt(args[2]);
            boolean allowUnsafeRenegoriation = args[3].trim().equalsIgnoreCase("true");
            final UnsafeRenegotiationTestTLSServer serverThread = new UnsafeRenegotiationTestTLSServer(InetAddress.getLocalHost(), port, args[0], args[1], allowUnsafeRenegoriation);
            Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    if (serverThread != null) {
                        serverThread.interrupt();
                    }
                }
            });            
        }else if(args.length == 5){
            int port = Integer.parseInt(args[3]);
            boolean debug = Boolean.parseBoolean(args[4]);
            if(debug) {
                System.out.println("Debuggin enabled!");
            }
            final TLSServer serverThread = new TLSServer(args[0], args[1], args[2], port, debug);
            serverThread.start();
            Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    if (serverThread != null) {
                        serverThread.shutdown();
                    }
                }
            });            
        }else{
            System.out.println("Invalid number of arguments!\n"
                    + "Usage: java -jar TinyTLSServer.jar Key store path, Password, Protocol version, Port, Debug mode enabled\n"
                    + "Usage: java -jar TinyTLSServer.jar Key store path, Password, Port, Allow unsecure renegotiation"
            );
        }
    }
}
