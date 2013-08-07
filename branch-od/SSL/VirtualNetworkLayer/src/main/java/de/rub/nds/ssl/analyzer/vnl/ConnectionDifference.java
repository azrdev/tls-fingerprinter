package de.rub.nds.ssl.analyzer.vnl;

public class ConnectionDifference {
	private String name;
	private Object a;
	private Object b;
	
	public ConnectionDifference(String name, Object a, Object b) {
		this.name = name;
		this.a = a;
		this.b = b;
	}
	
	public String toString() {
		return name + ": " + a + " <=> " + b;
	}

}
