package de.rub.nds.ssl.analyzer.executor;

import de.rub.nds.ssl.analyzer.AAnalyzerComponent;
import de.rub.nds.ssl.analyzer.AnalyzerResult;
import de.rub.nds.ssl.analyzer.TestResult;
import de.rub.nds.ssl.analyzer.fingerprinter.ETLSImplementation;
import de.rub.nds.ssl.analyzer.fingerprinter.FingerprintFuzzer;
import de.rub.nds.ssl.analyzer.fingerprinter.IFingerprinter;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocket;
import org.apache.log4j.Logger;

/**
 * Launcher service.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 16, 2013
 */
public abstract class Launcher {

    /**
     * Thread executor.
     */
    private static ExecutorService executor =
            Executors.newSingleThreadExecutor();
    /**
     * Log4j logger initialization.
     */
    private static Logger logger = Logger.getRootLogger();

    /**
     * Utility class without public constructor.
     */
    private Launcher() {
    }

    /**
     * Launch fingerprint scan.
     *
     * @param targetList List of targets to scan
     * @param components List of components to scan
     * @throws InterruptedException
     * @throws ExecutionException
     */
    public static void startScan(final String[] targetList,
            final EFingerprintTests[] components)
            throws InterruptedException, ExecutionException {
        // deep copy target list
        String[] targets = new String[targetList.length];
        System.arraycopy(targetList, 0, targets, 0, targetList.length);

        // invoke components
        List<TestResult[]> results;
        for (String tmpTarget : targets) {
            if (checkConnection(tmpTarget)) {
                results = invokeExecutor(components, tmpTarget);
                invokeAnalyzer(results);
            } else {
                logger.info("No connection to target: "
                        + tmpTarget + " possible.");
            }
        }
    }

    /**
     * Launch fingerprint fuzzing.
     *
     * @param targetList List of targets to scan
     * @param implementation Implementation of the target
     * @throws InterruptedException
     * @throws ExecutionException
     */
    public static void startFuzzing(final String[] targetList,
            final ETLSImplementation implementation)
            throws InterruptedException, ExecutionException {
        // deep copy target list
        String[] targets = new String[targetList.length];
        System.arraycopy(targetList, 0, targets, 0, targetList.length);

        // invoke components
        List<TestResult[]> results;
        for (String tmpTarget : targets) {
//            if (checkConnection(tmpTarget)) {
                results = invokeExecutor(EFingerprintTests.values(), tmpTarget);
                invokeFuzzer(results, implementation);
//            } else {
//                logger.info("No connection to target: "
//                        + tmpTarget + " possible.");
//            }
        }
    }

    /**
     * Checks if the target is reachable.
     *
     * @param target Target to check
     * @return True if the target is reachable
     */
    private static boolean checkConnection(final String target) {
        boolean result = false;

        URL url;
        HttpsURLConnection connection = null;
        try {
            /*
             * NOTE: It is very likely that HttpsURLConnection responds with an
             * unknown_certificate SSL/TLS alert, because it is not guaranteed
             * that the Root CA of the remote peer is in our trusted key store.
             */
            url = new URL(target);
            connection = (HttpsURLConnection) url.openConnection();
            connection.connect();
            result = true;
        } catch (ConnectException e) {
            result = false;
        } catch (IOException e) {
            // multiple scenarios lead to this eception - to be safe set true
            result = true;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }

        return result;
    }

    /**
     * Invokes the thread executor.
     *
     * @param components Componentns to be executed
     * @param target Targets for the instances
     * @return Component results
     * @throws InterruptedException
     * @throws ExecutionException
     */
    private static List<TestResult[]> invokeExecutor(
            final EFingerprintTests[] components, final String target)
            throws InterruptedException, ExecutionException {
        // fetch instances of components
        List<AAnalyzerComponent> instances =
                new ArrayList<AAnalyzerComponent>(components.length);

        Class<AAnalyzerComponent> implementer;
        AAnalyzerComponent tmpComponent;
        for (EFingerprintTests tmp : components) {
            try {
                implementer = tmp.getImplementer();
                tmpComponent = implementer.newInstance();
                tmpComponent.setTarget(target);
                tmpComponent.setAnalyzer(tmp.getAnalyzer());
                instances.add(tmpComponent);
            } catch (IllegalAccessException e) {
                logger.error("Illegal Access.", e);
            } catch (InstantiationException e) {
                logger.error("Problems during instantiation.", e);
            }
        }

        List<Future<TestResult[]>> futures = executor.invokeAll(instances);
        // wait for results (estimated 5 test per instance)
        List<TestResult[]> results =
                new ArrayList<TestResult[]>(instances.size() * 5);
        for (Future<TestResult[]> future : futures) {
            if (future.isCancelled()) {
                continue;
            }
            results.add(future.get());
        }

        return results;
    }

    /**
     * Invoke analyzer(s) to analyze result(s).
     *
     * @param results Results to be analyzed
     */
    private static void invokeAnalyzer(final List<TestResult[]> results) {
        List<AnalyzerResult> analyzerResults = new ArrayList<AnalyzerResult>();
        IFingerprinter analyzer;
        for (TestResult[] resultWrappers : results) {
            for (TestResult tmpResult : resultWrappers) {
                try {
                    logger.info("Analyzing results from "
                            + tmpResult.getTestName()
                            + " with Analyzer "
                            + tmpResult.getAnalyzer().getCanonicalName());;
                    analyzer = tmpResult.getAnalyzer().newInstance();
                    analyzer.init(tmpResult.getParameters());
                    analyzerResults.add(analyzer.analyze(tmpResult.
                            getTraceList()));
                } catch (IllegalAccessException e) {
                    logger.error("Illegal Access.", e);
                } catch (InstantiationException e) {
                    logger.error("Problems during instantiation.", e);
                }
            }
        }

        // TODO mke me nice
        Reporter.generateReport(analyzerResults.
                toArray(new AnalyzerResult[analyzerResults.size()]), logger);
    }

    private static void invokeFuzzer(final List<TestResult[]> results,
            final ETLSImplementation implementation) {
        FingerprintFuzzer analyzer = new FingerprintFuzzer();
        for (TestResult[] resultWrappers : results) {
            for (TestResult tmpResult : resultWrappers) {
                analyzer.init(tmpResult.getParameters());
                analyzer.setImplementation(implementation);
                analyzer.setTestcase(tmpResult.getTestName());
                analyzer.analyze(tmpResult.getTraceList());
            }
        }
    }
}
