package de.rub.nds.ssl.analyzer.executor;

/**
 * Listing of all available attacks.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Jan 15, 2013
 */
public enum EAttacks {
        ;
//    BLEICHENBACHER("Bleichenbacher Attack", Bleichenbacher.class);
    
    /**
     * Attack description.
     */
    private String description;
    /**
     * Attack implementer.
     */
    private Class implementer;

    /**
     * Prepare Attack listing,
     * 
     * @param description Attack description
     * @param implementer Attack implementer
     */
    private EAttacks(final String description, final Class implementer) {
        this.description = description;
        this.implementer = implementer;
    }
    
    /**
     * Getter for attack description.
     * @return Attack description
     */
    public String getDescription() {
        return this.description;
    }
    
    /**
     * Getter for attack implementer.
     * @return Attack implementer
     */
    public Class getImplementer() {
        return this.implementer;
    }
}
