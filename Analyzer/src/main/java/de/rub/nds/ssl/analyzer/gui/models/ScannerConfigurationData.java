package de.rub.nds.ssl.analyzer.gui.models;

import de.rub.nds.ssl.analyzer.executor.EFingerprintTests;

/**
 * Table model for scanner configuration.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 15, 2013
 */
public class ScannerConfigurationData extends AConfigurationData {

    public ScannerConfigurationData() {
        super();
        EFingerprintTests[] tests = EFingerprintTests.values();
        Object[][] tmpConfiguration = new Object[tests.length][3];
        for (int i = 0; i < tests.length; i++) {
            tmpConfiguration[i] = new Object[]{tests[i].getDescription(), true,
                tests[i]};
        }

        setConfiguration(tmpConfiguration);

        Column[] tmpColumns = new Column[]{
            new Column("Component", false),
            new Column("Enabled", true)
        };
        setColumns(tmpColumns);
    }
}
