package de.rub.nds.research.ssl.stack.tests.analyzer;

import de.rub.nds.research.ssl.stack.protocols.ARecordFrame;

public interface IMessageAnalyzer {
	
	public void compareMessages(ARecordFrame currentRecord, ARecordFrame oldRecord);

}
