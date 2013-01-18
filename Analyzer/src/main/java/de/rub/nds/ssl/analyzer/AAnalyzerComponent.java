package de.rub.nds.ssl.analyzer;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.Callable;

/**
 * Analyzer component prototype.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 16, 2013
 */
public abstract class AAnalyzerComponent implements Callable<ResultWrapper[]> {

    private String target;

    /**
     * Getter for target URL.
     *
     * @return Target URL
     */
    public final String getTarget() {
        return target;
    }

    /**
     * Setter for target URL.
     *
     * @param target Target URL to set
     */
    public final void setTarget(String target) {
        this.target = target;
    }

    /**
     * Returns the target as URL.
     * @return Target as URL
     */
    public final URL targetAsURL() {
        URL result = null;
        try {
            if (target != null) {
                result = new URL(target);
            }
        } catch (MalformedURLException e) {
            // TODO: log me
        }
        
        return result;
    }
    
    /**
     * Returns the target port.
     * @return Port of the target
     */
    public final int getTargetPort() {
        int result = -1;
        URL url = targetAsURL();
        if(url != null) {
            result = url.getPort();
            if(result < 0) {
                result = url.getDefaultPort();
            }
        }
        
        return result;
    }
    
    /**
     * Returns the target host.
     * @return Host address of the target
     */
    public final String getTargetHost() {
        String host = null;
        URL url = targetAsURL();
        if(url != null) {
            host = url.getHost();
        }
        
        return host;
    }
}
