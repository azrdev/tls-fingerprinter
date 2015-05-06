package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;
import de.rub.nds.virtualnetworklayer.pcap.Pcap;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * System test of the whole TLS Fingerprinting: assert that MITM testcase throws "changed"
 * fingerprint reports
 */
public class FingerprintingTest {
    private final String pcap_fedora_nginx = getClass().getResource("Fedora21_nginx1.6.3_FF37.pcap").getPath();
    private final String pcap_ubuntu_apache = getClass().getResource("Ubuntu1404_apache2.4.7_FF37.pcap").getPath();
    private final String pcap_win_apache = getClass().getResource("Win7_apache2.4.12_FF37.pcap").getPath();
    private final String pcap_win_iis = getClass().getResource("Win7_IIS_FF37.pcap").getPath();

    private SslReportingConnectionHandler handler;
    private Pcap pcap;
    private final ReportCounter reportCounter = new ReportCounter();

    private static class ReportCounter implements FingerprintReporter {
        private int openNew;
        private int openUpdates;
        private int openChanges;
        private int openGuesses;

        public void resetCounters(int new_and_guesses, int updates, int changes) {
            synchronized (this) {
                openNew = new_and_guesses;
                openUpdates = updates;
                openChanges = changes;
                openGuesses = new_and_guesses;
            }
        }

        public void assertFinished() {
            synchronized (this) {
                assertEquals("Unexpected number of 'new' reports", 0, openNew);
                assertEquals("Unexpected number of 'update' reports", 0, openUpdates);
                assertEquals("Unexpected number of 'change' reports", 0, openChanges);
                assertEquals("Unexpected number of 'guess' reports", 0, openGuesses);
            }
        }

        @Override
        public void reportChange(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint, Set<TLSFingerprint> previousFingerprints) {
            synchronized (this) {
                --openChanges;
            }
        }

        @Override
        public void reportUpdate(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
            synchronized (this) {
                --openUpdates;
            }
        }

        @Override
        public void reportNew(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
            synchronized (this) {
                --openNew;
            }
        }

        @Override
        public void reportArtificial(SessionIdentifier sessionIdentifier, TLSFingerprint fingerprint) {
            synchronized (this) {
                --openGuesses;
            }
        }
    }

    @Before
    public void setUp() {
        handler = new SslReportingConnectionHandler(false);
        handler.setFingerprintReporting(true, null, null, null, false, false, true);
        handler.getFingerprintListener().addFingerprintReporter(reportCounter);
    }

    @Test
    public void testSingleFedora() {
        reportCounter.resetCounters(2, 3, 0);
        File f = new File(pcap_fedora_nginx);
        pcap = Pcap.openOffline(f);
        handler.setPcap(pcap);
        assertEquals(Pcap.Status.Success, pcap.loop(handler));
        reportCounter.assertFinished();
    }

    @Test
    public void testSingleUbuntuApache() {
        reportCounter.resetCounters(2, 1, 0);
        pcap = Pcap.openOffline(new File(pcap_ubuntu_apache));
        handler.setPcap(pcap);
        assertEquals(Pcap.Status.Success, pcap.loop(handler));
        reportCounter.assertFinished();
    }

    @Test
    public void testSingleWinApache() {
        reportCounter.resetCounters(2, 4, 0);
        pcap = Pcap.openOffline(new File(pcap_win_apache));
        handler.setPcap(pcap);
        assertEquals(Pcap.Status.Success, pcap.loop(handler));
        reportCounter.assertFinished();
    }

    @Test
    public void testSingleWinIIS() {
        reportCounter.resetCounters(2, 3, 0);
        pcap = Pcap.openOffline(new File(pcap_win_iis));
        handler.setPcap(pcap);
        assertEquals(Pcap.Status.Success, pcap.loop(handler));
        reportCounter.assertFinished();
    }

    /**
     * Test interaction of the test pcaps: i.e. change reports of similar fingerprints
     */
    @Test
    public void testChangedFingerprints() {
        // loop file fedora nginx
        reportCounter.resetCounters(2, 3, 0);
        pcap = Pcap.openOffline(new File(pcap_fedora_nginx));
        handler.setPcap(pcap);
        assertEquals(Pcap.Status.Success, pcap.loop(handler));
        reportCounter.assertFinished();

        // loop file ubuntu apache
        reportCounter.resetCounters(0, 2, 1);
        pcap = Pcap.openOffline(new File(pcap_ubuntu_apache));
        handler.setPcap(pcap);
        assertEquals(Pcap.Status.Success, pcap.loop(handler));
        reportCounter.assertFinished();

        // loop file win apache
        reportCounter.resetCounters(0, 6, 0);
        pcap = Pcap.openOffline(new File(pcap_win_apache));
        handler.setPcap(pcap);
        assertEquals(Pcap.Status.Success, pcap.loop(handler));
        reportCounter.assertFinished();

        // loop file win IIS
        reportCounter.resetCounters(1, 3, 1);
        pcap = Pcap.openOffline(new File(pcap_win_iis));
        handler.setPcap(pcap);
        assertEquals(Pcap.Status.Success, pcap.loop(handler));
        reportCounter.assertFinished();
    }
}