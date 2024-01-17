import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import javax.swing.table.DefaultTableModel;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import jpcap.packet.ICMPPacket;

public class PacketContents implements PacketReceiver {

    public static TCPPacket tcp;
    public static UDPPacket udp;
    public static ICMPPacket icmp;
    

    public static List<Object[]> rowList = new ArrayList<Object[]>();
    
    public static DatabaseHandler dbHandler = new DatabaseHandler();

    static {
        try {
            dbHandler.connect("sample.db");
        } catch (SQLException e) {
            e.printStackTrace();
            // Handle the error appropriately
        }
    }

    @Override
    public void receivePacket(Packet packet) {

        if (packet instanceof TCPPacket) {
            tcp = (TCPPacket) packet;

            Object[] row = {sniffer.No, tcp.length, tcp.src_ip, tcp.dst_ip, "TCP"};

            rowList.add(new Object[]{sniffer.No, tcp.length, tcp.src_ip, tcp.dst_ip, "TCP", tcp.src_port, tcp.dst_port,
                tcp.ack, tcp.ack_num, tcp.data, tcp.sequence, tcp.offset, tcp.header});

            DefaultTableModel model = (DefaultTableModel) sniffer.packetTable.getModel();
            model.addRow(row);
            
            int length = tcp.length;
            String sourceIP = tcp.src_ip.getHostAddress();
            String destinationIP = tcp.dst_ip.getHostAddress();
            int srcPort =0;
            if(tcp != null && tcp.src_port != 0)
            	srcPort = tcp.src_port;
            int destinationPort = 0;
            if(tcp != null && tcp.dst_port != 0)
            	destinationPort=	tcp.dst_port;
            String protocol = "TCP";
            
            try {
                dbHandler.insertPacket( sourceIP, destinationIP,length, protocol,srcPort,destinationPort );
                System.out.println("Inserted to DB");
            } catch (SQLException e) {
                e.printStackTrace();
                // Handle the error appropriately
            }
            
            sniffer.No++;

        } else if (packet instanceof UDPPacket) {

            udp = (UDPPacket) packet;

            Object[] row = {sniffer.No, udp.length, udp.src_ip, udp.dst_ip, "UDP"};
            rowList.add(new Object[]{sniffer.No, udp.length, udp.src_ip, udp.dst_ip, "UDP", udp.src_port, udp.dst_port,
                udp.data, udp.offset, udp.header});

            DefaultTableModel model = (DefaultTableModel) sniffer.packetTable.getModel();
            model.addRow(row);
            
            int length = udp.length;
            String sourceIP = udp.src_ip.getHostAddress();
            String destinationIP = udp.dst_ip.getHostAddress();
            String protocol = "UDP";
            int srcPort =0;
            if(udp != null && udp.src_port != 0)
            	srcPort = udp.src_port;
            int destinationPort = 0;
            if(udp != null && udp.dst_port != 0)
            	destinationPort=udp.dst_port;
            
            try {
            	 dbHandler.insertPacket( sourceIP, destinationIP,length, protocol,srcPort,destinationPort );
            } catch (SQLException e) {
                e.printStackTrace();
                // Handle the error appropriately
            }
            
            sniffer.No++;

        } else if (packet instanceof ICMPPacket) {

            icmp = (ICMPPacket) packet;

            Object[] row = {sniffer.No, icmp.length, icmp.src_ip, icmp.dst_ip, "ICMP"};
            rowList.add(new Object[]{sniffer.No, icmp.length, icmp.src_ip, icmp.dst_ip, "ICMP", icmp.checksum, icmp.header,
                icmp.offset, icmp.orig_timestamp, icmp.recv_timestamp, icmp.trans_timestamp, icmp.data});

            DefaultTableModel model = (DefaultTableModel) sniffer.packetTable.getModel();
            model.addRow(row);
            
            int length = icmp.length;
            String sourceIP = icmp.src_ip.getHostAddress();
            String destinationIP = icmp.dst_ip.getHostAddress();
            String protocol = "ICMP";
            int srcPort =0;
            int destinationPort = 0;
            
            try {
            	 dbHandler.insertPacket( sourceIP, destinationIP,length, protocol,srcPort,destinationPort );
            } catch (SQLException e) {
                e.printStackTrace();
                // Handle the error appropriately
            }
            sniffer.No++;

        }
    }
}
