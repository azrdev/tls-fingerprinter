package de.rub.nds.ssl.stack.analyzer.capture;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ConnectionDifferenceSet {
	private Set<ConnectionDifference> differences;
	public ConnectionDifferenceSet() {
		differences = new HashSet<ConnectionDifference>();
	}
	
	public void addDifference(ConnectionDifference cd) {
		differences.add(cd);
	}
	
	public boolean isEmpty() {
		return differences.isEmpty();
	}
	
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("Differences:");
		for (ConnectionDifference cd : differences) {
			sb.append("\n" + cd.toString());
		}
		return new String(sb);
	}
	
	public static ConnectionDifferenceSet generateFromMap(Map<String, Object> a, Map<String, Object> b) {
		HashSet<String> keys = new HashSet<String>();
		ConnectionDifferenceSet cds = new ConnectionDifferenceSet();
		keys.addAll(a.keySet());
		keys.addAll(b.keySet());
		for (String s : keys) {
			Object oa = a.get(s);
			Object ob = b.get(s);
			if (oa != null) {
				if (!oa.equals(ob)) {
					cds.addDifference(new ConnectionDifference(s, oa, ob));
				}
			} else if (ob == null) {
				cds.addDifference(new ConnectionDifference(s, oa, ob));
			}
		}
		return cds;
	}
	

}
