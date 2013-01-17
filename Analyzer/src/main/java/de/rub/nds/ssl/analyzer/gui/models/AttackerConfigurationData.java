package de.rub.nds.ssl.analyzer.gui.models;

import de.rub.nds.ssl.analyzer.executor.EAttacks;

/**
 * Table model for attacker configuration.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 16, 2013
 */
public class AttackerConfigurationData extends AConfigurationData {

    public AttackerConfigurationData() {
        EAttacks[] attacks = EAttacks.values();
        Object[][] tmpConfiguration = new Object[attacks.length][];
        for (int i = 0; i < attacks.length; i++) {
            tmpConfiguration[i] = new Object[]{attacks[i].getDescription(), true,
                attacks[i]};
        }

        setConfiguration(tmpConfiguration);

        Column[] tmpColumns = new Column[]{
            new Column("Component", false),
            new Column("Enabled", true)
        };
        setColumns(tmpColumns);
    }
}
