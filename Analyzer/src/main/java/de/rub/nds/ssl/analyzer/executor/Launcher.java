package de.rub.nds.ssl.analyzer.executor;

import de.rub.nds.ssl.analyzer.AAnalyzerComponent;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Launcher service.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 16, 2013
 */
public abstract class Launcher {

    private static ExecutorService executor = Executors.newCachedThreadPool();

    /**
     * Utility class without public constructor.
     */
    private Launcher() {
    }

    public static void start(final String[] targetList, final Class[] components)
            throws InterruptedException {
        // deep copy target list
        String[] targets = new String[targetList.length];
        System.arraycopy(targetList, 0, targets, 0, targetList.length);

        // fetch instances of components
        List<AAnalyzerComponent> instances =
                new ArrayList<AAnalyzerComponent>(components.length);
        for (Class tmpComponent : components) {
            try {
                instances.add((AAnalyzerComponent) tmpComponent.newInstance());
            } catch (IllegalAccessException e) {
                // TODO: log me
            } catch (InstantiationException e) {
                // TODO: log me
            }
        }

        // invoke components
        List<Future<Object>> results;
        for (String tmpTarget : targets) {
            for (AAnalyzerComponent tmpComponent : instances) {
                tmpComponent.setTarget(tmpTarget);
            }
            results = executor.invokeAll(instances);

            // wait for results
        }
    }

    public static void main(String args[]) throws InterruptedException {
        Launcher.start(new String[]{"https://www.rub.de"},
                new Class[]{EFingerprintTests.CCS.getImplementer()});
    }
}
