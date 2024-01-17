import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class DatabaseHandler {
    private Connection connection;
    private PreparedStatement insertPacketStmt;

    public void connect(String dbFilePath) throws SQLException {
    	 connection = DriverManager.getConnection("jdbc:sqlite:sample.db");
    	// Create the packets table if it does not exist
    	 connection.createStatement().execute(
    			    "CREATE TABLE IF NOT EXISTS packets (" +
    			    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    			    "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, " +
    			    "source_ip TEXT, " +
    			    "destination_ip TEXT, " +
    			    "length INTEGER, " +
    			    "protocol TEXT, " +
    			    "source_port INTEGER NULL, " + // Allow NULL values for source_port
    			    "destination__port INTEGER NULL" + // Allow NULL values for destination__port
    			    ")"
    			);

             String insertSQL = "INSERT INTO packets (source_ip, destination_ip, length, protocol,source_port, destination__port) VALUES (?, ?, ?, ?, ?, ?)";
             
             insertPacketStmt = connection.prepareStatement(insertSQL);
    }
    public void insertPacket(String sourceIP, String destinationIP, int length, String protocol, int srcPort, int dstPort) throws SQLException {
    	if (connection != null && !connection.isClosed() && insertPacketStmt != null) {
    		insertPacketStmt.setString(1, sourceIP);
	        insertPacketStmt.setString(2, destinationIP);
	        insertPacketStmt.setInt(3, length);
	        insertPacketStmt.setString(4, protocol);
	        insertPacketStmt.setInt(3, srcPort);
	        insertPacketStmt.setInt(3, dstPort);
	        insertPacketStmt.executeUpdate();
    }
    }
   
    public void disconnect() throws SQLException {
        if (insertPacketStmt != null) {
            insertPacketStmt.close();
        }
        if (connection != null && !connection.isClosed()) {
            connection.close();
        }
    }
    
    public void printAllPackets() {
       String query = "SELECT * FROM packets";
        try {
			if (connection != null && !connection.isClosed()) {
			    try (Statement stmt = connection.createStatement();
			         ResultSet rs = stmt.executeQuery(query)) {

			        while (rs.next()) {
			            
			            
			            String sourceIP = rs.getString("source_ip");
			            String destinationIP = rs.getString("destination_ip");
			            int length = rs.getInt("length");
			            String protocol = rs.getString("protocol");

			            System.out.println("Length: " + length +
			                               ", Source IP: " + sourceIP + ", Destination IP: " + destinationIP +
			                               ", Protocol: " + protocol);
			        }
			    } catch (SQLException e) {
			        e.printStackTrace();
			    }
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
    }
    public boolean isConnectionClosed() {
        try {
            return connection == null || connection.isClosed();
        } catch (SQLException e) {
            // Handle exception
            e.printStackTrace();
            return true; // If there's an exception, assume the connection is not valid
        }
    }

    
    public ResultSet getFilteredPackets(String filterType, String filterText) throws SQLException {
        String query = "";
        PreparedStatement stmt = null;

        switch (filterType) {
            case "Source Port":
                query = "SELECT * FROM packets WHERE source_port = ?";
                stmt = connection.prepareStatement(query);
                stmt.setInt(1, Integer.parseInt(filterText));
                break;
            case "Destination Port":
                query = "SELECT * FROM packets WHERE destination_port = ?";
                stmt = connection.prepareStatement(query);
                stmt.setInt(1, Integer.parseInt(filterText));
                break;
            case "Source IP":
                query = "SELECT * FROM packets WHERE source_ip = ?";
                stmt = connection.prepareStatement(query);
                stmt.setString(1, filterText);
                break;
            case "Destination IP":
                query = "SELECT * FROM packets WHERE destination_ip = ?";
                stmt = connection.prepareStatement(query);
                stmt.setString(1, filterText);
                break;
            case "Protocol":
                query = "SELECT * FROM packets WHERE protocol = ?";
                stmt = connection.prepareStatement(query);
                stmt.setString(1, filterText);
                break;
            default:
                // Handle invalid filterType
                throw new IllegalArgumentException("Invalid filter type: " + filterType);
        }

        if (stmt != null) {
            return stmt.executeQuery();
        } else {
            // Handle error or return an empty result set
            throw new SQLException("Failed to create SQL statement.");
        }
    }

}