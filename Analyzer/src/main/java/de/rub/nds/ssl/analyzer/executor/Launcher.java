package de.rub.nds.ssl.analyzer.executor;

import de.rub.nds.ssl.analyzer.AAnalyzerComponent;
import de.rub.nds.ssl.analyzer.ResultWrapper;
import de.rub.nds.ssl.analyzer.fingerprinter.IFingerprinter;
import de.rub.nds.ssl.analyzer.fingerprinter.TestHashAnalyzer;
import de.rub.nds.ssl.analyzer.parameters.AParameters;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

/**
 * Launcher service.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 16, 2013
 */
public abstract class Launcher {

    private static ExecutorService executor = Executors.newSingleThreadExecutor();
    private static Logger logger = Logger.getRootLogger();

    /**
     * Utility class without public constructor.
     */
    private Launcher() {
    }

    public static void start(final String[] targetList,
            final EFingerprintTests[] components)
            throws InterruptedException, ExecutionException {
        // deep copy target list
        String[] targets = new String[targetList.length];
        System.arraycopy(targetList, 0, targets, 0, targetList.length);

        // fetch instances of components
        List<AAnalyzerComponent> instances =
                new ArrayList<AAnalyzerComponent>(components.length);
        for (EFingerprintTests tmp : components) {
            try {
                instances.add(
                        (AAnalyzerComponent) tmp.getImplementer().newInstance());
            } catch (IllegalAccessException e) {
                // TODO: log me
            } catch (InstantiationException e) {
                // TODO: log me
            }
        }

        // invoke components
        List<ResultWrapper[]> results;
        for (String tmpTarget : targets) {
            results = invokeExecutor(instances, tmpTarget);
//            invokeAnalyzer(results);
        }
    }

    private static List<ResultWrapper[]> invokeExecutor(
            final List<AAnalyzerComponent> instances, final String target)
            throws InterruptedException, ExecutionException {
        for (AAnalyzerComponent tmpComponent : instances) {
            tmpComponent.setTarget(target);
        }

        List<Future<ResultWrapper[]>> futures = executor.invokeAll(instances);
        // wait for results (estimated 5 test per instance)
        List<ResultWrapper[]> results =
                new ArrayList<ResultWrapper[]>(instances.size() * 5);
        for (Future<ResultWrapper[]> future : futures) {
            if (future.isCancelled()) {
                continue;
            }
            results.add(future.get());
        }

        return results;
    }

    private static void invokeAnalyzer(List<ResultWrapper[]> results) {
        IFingerprinter analyzer = new TestHashAnalyzer();
        for (ResultWrapper[] resultWrappers : results) {
            for (ResultWrapper tmpResult : resultWrappers) {
                analyzer.init(tmpResult.getParameters());
                analyzer.analyze(tmpResult.getTraceList());
            }
        }
    }

    public static void main(String args[]) throws InterruptedException,
            ExecutionException {
        PropertyConfigurator.configure("logging.properties");
        Launcher.start(new String[]{"https://www.rub.de"},
                new EFingerprintTests[]{EFingerprintTests.GOOD, EFingerprintTests.HANDSHAKE_ENUM, EFingerprintTests.CCS});
    }
}
