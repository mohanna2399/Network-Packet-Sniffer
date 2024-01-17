import javax.swing.*;
import javax.swing.JFrame;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class DatabaseUI extends JFrame {
    private JTable dataTable;
    private JButton filterButton;
    private JComboBox<String> filterComboBox;
    private JTextField filterValueField;
    private DatabaseHandler dbHandler;
    public DatabaseUI() {
        setTitle("Database Viewer");
        setSize(600, 400);
        setLayout(new BorderLayout());
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        
        dbHandler = new DatabaseHandler();
        try {
            dbHandler.connect("sample.db");
            dbHandler.printAllPackets();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        // Table setup
        dataTable = new JTable();
        JScrollPane scrollPane = new JScrollPane(dataTable);
        add(scrollPane, BorderLayout.CENTER);

        // Filter setup
        JPanel filterPanel = new JPanel();
        filterComboBox = new JComboBox<>(new String[]{"Select Filter", "Protocol", "Source Port", "Destination Port", "Source IP", "Destination IP"});
        filterComboBox.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                updateFilterInputPanel();
            }
        });

        filterValueField = new JTextField(20);
        filterButton = new JButton("Filter");
        filterButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                applyFilter();
            }
        });

        filterPanel.add(filterComboBox);
        filterPanel.add(filterValueField);
        filterPanel.add(filterButton);
        add(filterPanel, BorderLayout.NORTH);
        
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                dispose();
            	System.exit(0);
            }
        });
    }

    private void updateFilterInputPanel() {
        String selectedFilter = filterComboBox.getSelectedItem().toString();

        if ("Select Filter".equals(selectedFilter)) {
            filterValueField.setEnabled(false);
        } else {
            filterValueField.setEnabled(true);
        }
    }

    private void applyFilter() {
        String selectedFilter = filterComboBox.getSelectedItem().toString();
        String filterValue = filterValueField.getText();

        if ("Select Filter".equals(selectedFilter)) {
            JOptionPane.showMessageDialog(this, "Please select a filter type.");
            return;
        }

        ResultSet filteredResultSet = null;
        try {
        	filterValue = filterValue.toUpperCase();
			filteredResultSet = dbHandler.getFilteredPackets(selectedFilter, filterValue);
			displayData(filteredResultSet);
        } catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
    }

    private void displayData(ResultSet rs) throws SQLException {
        DefaultTableModel model = new DefaultTableModel(new String[]{"Source IP", "Destination IP", "Length", "Protocol"}, 0);
        while (rs.next()) {            
            String sourceIP = rs.getString("source_ip");
            String destinationIP = rs.getString("destination_ip");
            int length = rs.getInt("length");
            String protocol = rs.getString("protocol");
            int srcPort = rs.getInt("source_port");
            int dstPort = rs.getInt("destination__port");
            model.addRow(new Object[]{sourceIP, destinationIP, length, protocol,srcPort, dstPort});
        }
        dataTable.setModel(model);
    }
    public static void main(String[] args) {
    	
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                new DatabaseUI().setVisible(true);
            }
        });
        
    }
}
