package de.rub.nds.research.ssl.stack.tests.analyzer.db;

import java.io.ByteArrayInputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;

import de.rub.nds.research.ssl.stack.protocols.commons.ECipherSuite;

public class Database {
	
	private Connection conn;
	
	public Database() {
		try {
			this.connectDB();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void connectDB() throws Exception {
		Class.forName("com.mysql.jdbc.Driver");
		conn = DriverManager.getConnection("jdbc:mysql://localhost/fingerprint?"
				+ "user=tester&password=pentest");
	}
	
	public ResultSet readValue() throws Exception {
		java.sql.PreparedStatement prepared = conn.prepareStatement("select value from fingerprint.test_parameters");
		return prepared.executeQuery();
	}
	
	public void insertClientHelloBehaviour(byte [] protocolVersion,
			byte [] cipherSuites, int randomLength,
			int sessionIdLength, byte [] compMethod, String alert, String impl) throws Exception {
		ByteArrayInputStream bais = new ByteArrayInputStream(protocolVersion);
		java.sql.PreparedStatement prepared = conn.prepareStatement("insert into fingerprint.client_hello_behaviour"
				+ " values (default,?,?,?,?,?,?,?)");
		prepared.setBinaryStream(1, bais);
		bais = new ByteArrayInputStream(cipherSuites);
		prepared.setBinaryStream(2, bais);
		prepared.setInt(3, randomLength);
		prepared.setInt(4, sessionIdLength);
		bais = new ByteArrayInputStream(compMethod);
		prepared.setBinaryStream(5, bais);
		prepared.setString(6, alert);
		prepared.setString(7, impl);
		prepared.executeUpdate();
		
	}
	
	public void writeToDB(int testrun, String name, String status,
			Timestamp time, String parameter, byte [] bytes) throws Exception {
		ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
		java.sql.PreparedStatement prepared = conn.prepareStatement("insert into fingerprint.test_parameters"
				+ " values (default,?,?,?,?,?,?)");
		prepared.setInt(1, testrun);
		prepared.setString(2, name);
		prepared.setString(3, status);
		prepared.setTimestamp(4, time);
		prepared.setString(5, parameter);
		prepared.setBinaryStream(6, bais);
		prepared.executeUpdate();
	}
	
	public void closeDB() throws Exception {
		conn.close();
	}

}
