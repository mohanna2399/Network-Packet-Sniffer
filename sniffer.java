import jpcap.packet.Packet;
import jpcap.*;
import jpcap.JpcapWriter;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.xml.bind.DatatypeConverter;


import java.util.List;

public class sniffer extends JFrame{
	
//	private DatabaseHandler dbHandler = new DatabaseHandler();
	
    
    public static javax.swing.JTextArea packetTextArea;
    private javax.swing.JTextArea hexTextArea;
    
    private javax.swing.JToolBar topToolBar;
    
    public static javax.swing.JTable packetTable;
    public static java.awt.Button captureButton;
    public static javax.swing.JComboBox<String> filter_options;
    private javax.swing.JLabel filterLabel;
    private javax.swing.JLabel packetLabel;
    private javax.swing.JLabel hexLabel;
   
    private javax.swing.JScrollPane textScroll;
    private javax.swing.JScrollPane hexScroll;
    private javax.swing.JScrollPane packetScroll;
    
    public static java.awt.Button listButton;
    public static java.awt.Button saveButton;
    public static java.awt.Button stopButton;
    
    
    public sniffer() {
        initComponents();
        captureButton.setEnabled(false);
        stopButton.setEnabled(false);
        saveButton.setEnabled(false);
        filter_options.setEnabled(false);
        setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
        
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                
            	
            	try {
               // 	PacketContents.dbHandler.printAllPackets();
                	System.out.print("display");
                    PacketContents.dbHandler.disconnect();
                    
                } catch (SQLException er) {
                    er.printStackTrace();
                }
            	   
            onWindowClosing();

                
            }
        });
    }
	private void onWindowClosing() {
	    int response = JOptionPane.showConfirmDialog(this,
	            "Do you want to view the old data from the database?",
	            "Confirm",
	            JOptionPane.YES_NO_OPTION,
	            JOptionPane.QUESTION_MESSAGE);
	
	        if (response == JOptionPane.YES_OPTION) {
	            // Open DatabaseUI
	        	//this.setVisible(false);
	        	DatabaseUI databaseUI = new DatabaseUI();
	       	 	databaseUI.setVisible(true);
	            
	        }
	        else {
	        	
	        	try {
	            	PacketContents.dbHandler.printAllPackets();
	            	//System.out.print("display");
	                PacketContents.dbHandler.disconnect();
	                this.dispose();
	                System.exit(0);
	                    
	               
	            } catch (SQLException e) {
	                e.printStackTrace();
	            }
	        }
	}
    //Globals
    public static NetworkInterface[] NETWORK_INTERFACES;
    public static JpcapCaptor captor;
    jpcap_thread THREAD;
    public static int INDEX = 0;
    public static int flag = 0;
    public static int COUNTER = 0;
    boolean CaptureState = false;
    public static int No = 0;

    JpcapWriter writer = null;
    List<Packet> packetList = new ArrayList<>();

    
    public static String toHexadecimal(String text) throws UnsupportedEncodingException {
        byte[] myBytes = text.getBytes("UTF-8");

        return DatatypeConverter.printHexBinary(myBytes);
    }

    public static String customizeHexa(String text) {

        String out;
        out = text.replaceAll("(.{32})", "$1\n");
        return out.replaceAll("..(?!$)", "$0 ");
    }

    public void CapturePackets() {

        THREAD = new jpcap_thread() {

            public Object construct() {

                try {

                    captor = JpcapCaptor.openDevice(NETWORK_INTERFACES[INDEX], 65535, true, 1000);
                    if ("UDP".equals(filter_options.getSelectedItem().toString())) {
                        captor.setFilter("udp", true);
                    } else if ("TCP".equals(filter_options.getSelectedItem().toString())) {
                        captor.setFilter("tcp", true);
                    } else if ("ICMP".equals(filter_options.getSelectedItem().toString())) {
                        captor.setFilter("icmp", true);
                    }

                    while (CaptureState) {
                    	 Packet packet = captor.getPacket();
                         if (packet != null) {
	                        captor.processPacket(1, new PacketContents());
	                        packetList.add(captor.getPacket());
	                        System.out.println("Captured packet: " + packet);
	                        PacketContents packetContents = new PacketContents();
							packetContents.receivePacket(packet);
	                        
                         }
                    }
                    captor.close();

                } catch (Exception e) {
                    System.out.print(e);
                }
                return 0;
            }

            public void finished() {
                this.interrupt();
            }
        };

        THREAD.start();

    }

    @SuppressWarnings("unchecked")
    private void initComponents() {
    	
        topToolBar = new javax.swing.JToolBar();
        listButton = new java.awt.Button();
        filterLabel = new javax.swing.JLabel();
        filter_options = new javax.swing.JComboBox<>();
        captureButton = new java.awt.Button();
        stopButton = new java.awt.Button();
        saveButton = new java.awt.Button();
        packetScroll = new javax.swing.JScrollPane();
        packetTable = new javax.swing.JTable(){
            public boolean isCellEditable(int row, int column){
                return false;
            }
        };
        textScroll = new javax.swing.JScrollPane();
        packetTextArea = new javax.swing.JTextArea();
        hexScroll = new javax.swing.JScrollPane();
        hexTextArea = new javax.swing.JTextArea();
        packetLabel = new javax.swing.JLabel();
        hexLabel = new javax.swing.JLabel();
       
        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Packet Sniffer");
        setName("Packet Sniffer"); 

        topToolBar.setRollover(true);

        listButton.setActionCommand("List Interfaces");
        listButton.setBackground(new java.awt.Color(0, 0, 102));
        listButton.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        listButton.setForeground(new java.awt.Color(255, 255, 255));
        listButton.setLabel("List Interfaces");
        listButton.setPreferredSize(new java.awt.Dimension(90, 26));
        listButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                listButtonActionPerformed(evt);
            }
        });
        topToolBar.add(listButton);

        filterLabel.setText(" Filter");
        topToolBar.add(filterLabel);

        filter_options.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "---", "TCP", "UDP", "ICMP" }));
        filter_options.setPreferredSize(new java.awt.Dimension(320, 24));
        filter_options.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                filter_optionsActionPerformed(evt);
            }
        });
        topToolBar.add(filter_options);

        captureButton.setBackground(new java.awt.Color(0, 204, 0));
        captureButton.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        captureButton.setLabel("Capture");
        captureButton.setPreferredSize(new java.awt.Dimension(83, 24));
        captureButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                captureButtonActionPerformed(evt);
            }
        });
        topToolBar.add(captureButton);

        stopButton.setBackground(new java.awt.Color(255, 0, 51));
        stopButton.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        stopButton.setLabel("Stop");
        stopButton.setPreferredSize(new java.awt.Dimension(83, 24));
        stopButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                stopButtonActionPerformed(evt);
            }
        });
        topToolBar.add(stopButton);

        saveButton.setLabel("Save");
        saveButton.setPreferredSize(new java.awt.Dimension(83, 24));
        saveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveButtonActionPerformed(evt);
            }
        });
        topToolBar.add(saveButton);

        packetTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
            },
            new String [] {
                "No.", "Length", "Source", "Destination", "Protocol"
            }) 
        	{
            Class[] types = new Class [] {
                java.lang.Integer.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class, java.lang.String.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        packetTable.setRowHeight(20);
        packetTable.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                packetTableMouseClicked(evt);
            }
        });
        packetScroll.setViewportView(packetTable);

        packetTextArea.setEditable(false);
        packetTextArea.setColumns(20);
        packetTextArea.setRows(5);
        textScroll.setViewportView(packetTextArea);

        hexScroll.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        hexTextArea.setEditable(false);
        hexTextArea.setColumns(20);
        hexTextArea.setRows(5);
        hexScroll.setViewportView(hexTextArea);

        packetLabel.setText("Packet info:");

        hexLabel.setText("Hex view:");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(packetScroll)
            .addComponent(topToolBar, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(textScroll)
            .addComponent(hexScroll)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(packetLabel)
                    .addComponent(hexLabel))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(topToolBar, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(packetScroll, javax.swing.GroupLayout.PREFERRED_SIZE, 312, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(packetLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 9, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(textScroll, javax.swing.GroupLayout.PREFERRED_SIZE, 140, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(hexLabel)
                .addGap(1, 1, 1)
                .addComponent(hexScroll, javax.swing.GroupLayout.PREFERRED_SIZE, 108, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        pack();
    }//initComponents

    private void packetTableMouseClicked(java.awt.event.MouseEvent evt) {//event_packetTableMouseClicked

        Object obj = packetTable.getModel().getValueAt(packetTable.getSelectedRow(), 0);
        if (PacketContents.rowList.get((int) obj)[4] == "TCP") {

            packetTextArea.setText("Packet No: " + PacketContents.rowList.get((int) obj)[0]
                    + "\nSeq No: " + PacketContents.rowList.get((int) obj)[10]
                    + "\nProtocol: " + PacketContents.rowList.get((int) obj)[4]
                    + "\nSource IP: " + PacketContents.rowList.get((int) obj)[2]
                    + "\nDist IP: " + PacketContents.rowList.get((int) obj)[3]
                    + "\nLength: " + PacketContents.rowList.get((int) obj)[1]
                    + "\nSource Port: " + PacketContents.rowList.get((int) obj)[5]
                    + "\nDist Port: " + PacketContents.rowList.get((int) obj)[6]
                    + "\nAck: " + PacketContents.rowList.get((int) obj)[7]
                    + "\nAck No: " + PacketContents.rowList.get((int) obj)[8]
                    + "\nSequence No: " + PacketContents.rowList.get((int) obj)[10]
                    //+ "\nOffset: " + PacketContents.rowList.get((int) obj)[11]
                    + "\nHeader: " + PacketContents.rowList.get((int) obj)[12]
                    + "\nData: " + PacketContents.rowList.get((int) obj)[9]
            );

            try {
                hexTextArea.setText(customizeHexa(toHexadecimal(packetTextArea.getText())));
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(sniffer.class.getName()).log(Level.SEVERE, null, ex);
            }

        } else if (PacketContents.rowList.get((int) obj)[4] == "UDP") {
            packetTextArea.setText("Packet No: " + PacketContents.rowList.get((int) obj)[0]
                    + "\nProtocol:" + PacketContents.rowList.get((int) obj)[4]
                    + "\nSource IP: " + PacketContents.rowList.get((int) obj)[2]
                    + "\nDist IP: " + PacketContents.rowList.get((int) obj)[3]
                    + "\nLength: " + PacketContents.rowList.get((int) obj)[1]
                    + "\nSource Port: " + PacketContents.rowList.get((int) obj)[5]
                    + "\nDist Port: " + PacketContents.rowList.get((int) obj)[6]
                    + "\nOffset: " + PacketContents.rowList.get((int) obj)[8]
                    + "\nHeader: " + PacketContents.rowList.get((int) obj)[9]
                    + "\nData: " + PacketContents.rowList.get((int) obj)[7]
            );

            try {
                hexTextArea.setText(customizeHexa(toHexadecimal(packetTextArea.getText())));
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(sniffer.class.getName()).log(Level.SEVERE, null, ex);
            }

        } else if (PacketContents.rowList.get((int) obj)[4] == "ICMP") {
            packetTextArea.setText("Packet No: " + PacketContents.rowList.get((int) obj)[0]
                    + "\nProtocol:" + PacketContents.rowList.get((int) obj)[4]
                    + "\nSource IP: " + PacketContents.rowList.get((int) obj)[2]
                    + "\nDist IP: " + PacketContents.rowList.get((int) obj)[3]
                    + "\nLength: " + PacketContents.rowList.get((int) obj)[1]
                    + "\nChecksum: " + PacketContents.rowList.get((int) obj)[5]
                    + "\nHeader: " + PacketContents.rowList.get((int) obj)[6]
                    + "\nOffset: " + PacketContents.rowList.get((int) obj)[7]
                    + "\nOriginate TimeStamp: " + PacketContents.rowList.get((int) obj)[8] + "bits"
                    + "\nRecieve TimeStamp: " + PacketContents.rowList.get((int) obj)[9] + "bits"
                    + "\nTransmit TimeStamp: " + PacketContents.rowList.get((int) obj)[10] + "bits"
                    + "\nData: " + PacketContents.rowList.get((int) obj)[11]
            );

            try {
                hexTextArea.setText(customizeHexa(toHexadecimal(packetTextArea.getText())));
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(sniffer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }//event_packetTableMouseClicked

    private void captureButtonActionPerformed(java.awt.event.ActionEvent evt) {//event_captureButtonActionPerformed

        CaptureState = true;
        CapturePackets();
        saveButton.setEnabled(false);
        filter_options.setEnabled(false);
        listButton.setEnabled(false);
    }//event_captureButtonActionPerformed

    private void stopButtonActionPerformed(java.awt.event.ActionEvent evt) {//event_stopButtonActionPerformed
        CaptureState = false;
        THREAD.finished();
        saveButton.setEnabled(true);
        filter_options.setEnabled(true);
        listButton.setEnabled(true);
        
        try {
        	PacketContents.dbHandler.printAllPackets();
        	System.out.print("display");
            PacketContents.dbHandler.disconnect();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        if (PacketContents.dbHandler.isConnectionClosed()) {
	        System.out.println("Database connection is successfully closed.");
	    } else {
	        System.out.println("Database connection is still open.");
	    }
        
    }//event_stopButtonActionPerformed

    private void listButtonActionPerformed(java.awt.event.ActionEvent evt) {//event_listButtonActionPerformed
        
        InterfacesWindow nw = new InterfacesWindow();
    } //event_listButtonActionPerformed

    private void saveButtonActionPerformed(java.awt.event.ActionEvent evt) {//event_saveButtonActionPerformed
             writer = null;   
                try {
                   JFrame popup = new JFrame();
                   Object result = JOptionPane.showInputDialog(popup, "Enter FileName");
                   captor = JpcapCaptor.openDevice(NETWORK_INTERFACES[INDEX], 65535, true, 1000);
                   
                   if (result == null || result.toString().trim().isEmpty()) {
                       JOptionPane.showMessageDialog(null, "Invalid file name");
                       return;
                   }
                   writer = JpcapWriter.openDumpFile(captor, result.toString());

                   
                    for(int i = 0; i < packetList.size(); i++) {
                        Packet packet = packetList.get(i);
                        writer.writePacket(packet);
                        System.out.println("Writing packet: " + packet);
                    }
                    JOptionPane.showMessageDialog(null, "Data Saved Successfully");
                    
                    if (PacketContents.dbHandler.isConnectionClosed()) {
            	        System.out.println("Database connection is successfully closed.");
            	    } else {
            	        System.out.println("Database connection is still open.");
            	    }
                 // Ask user if they want to view the old database
         /*           int response = JOptionPane.showConfirmDialog(this,
                        "Do you want to view the old data from the database?",
                        "Confirm",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.QUESTION_MESSAGE);

                    if (response == JOptionPane.YES_OPTION) {
                        // Open DatabaseUI
                    	this.setVisible(false);
                    	DatabaseUI databaseUI = new DatabaseUI();
                   	 	databaseUI.setVisible(true);
                        
                    }
                    else 
                    {
                    this.dispose();
                    System.exit(0);
                    } */
                	} catch (IOException ex) {
	                    JOptionPane.showMessageDialog(null, "Data Save Failed");
	                    Logger.getLogger(sniffer.class.getName()).log(Level.SEVERE, null, ex);
	                }
                finally{
	                    if (writer != null) {
	                        writer.close();
	                    }
	                }
                
	                CaptureState = false;     

    }//event_saveButtonActionPerformed

    private void filter_optionsActionPerformed(java.awt.event.ActionEvent evt) {//event_filter_optionsActionPerformed
        // TODO add your handling code here:
    }//event_filter_optionsActionPerformed

    public static void main(String args[]) {
    	
    	try {
		 	//System.setProperty("java.library.path", "C:/Program Files (x86)/Jpcap");
	    	//System.loadLibrary("jpcap");
	    	
	    } catch (UnsatisfiedLinkError e) {
	      System.err.println("Native code library failed to load.\n" + e);
	      System.exit(1);
	    }
    	try {
    		javax.swing. UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
        
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(sniffer.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(sniffer.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(sniffer.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(sniffer.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
       
        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
           public void run() {
               new sniffer().setVisible(true);
               
            }
        });
        
        
    }
   
    
    

}
