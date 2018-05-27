package com.wchstrife;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.*;

import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Date;
import java.util.Scanner;

import static com.wchstrife.Util.Utils.macByteToString;

public class ARP {

    //当前默认打开的网卡
    public static NetworkInterface DEVICE = JpcapCaptor.getDeviceList()[0];
    //本机的IP
    public static String LOCALIP = "";
    //文件输出地址
    private static String FILEPATH = "./log.txt";

    /**
     * 获取本机上所有的网卡，注意选择目前正在使用的网卡
     * @return 当前正在使用的网卡，这里默认为第0个无线网卡
     */
    public static NetworkInterface getAllDevices(){

     NetworkInterface[] devices = JpcapCaptor.getDeviceList();

     /*
     遍历本电脑上所有的网卡
      */
     for (NetworkInterface n : devices){
         System.out.println("网卡名称" + n.name + "     |     " + "描述："  + n.description);
         System.out.println("MAC地址：" + macByteToString(n.mac_address));
     }

     System.out.println("-------------------------------------------");

     return devices[0];
 }

    /**
     * 根据传入的ip查找对应的MAC地址，通过ARP广播的形式
     * @param
     * @return
     */
    public static byte[] getMACByIp(String ip) throws IOException{
        JpcapCaptor jc = JpcapCaptor.openDevice(DEVICE, 2000, false, 3000);//打开网络设备
        JpcapSender sender = jc.getJpcapSenderInstance();   // 用来发送报文的发送器
        InetAddress senderIP = InetAddress.getByName(LOCALIP);  //本地主机的IP
        InetAddress targetIP = InetAddress.getByName(ip);   //目标主机的IP

        //构造ARP的首部以及发送地址
        ARPPacket arp = new ARPPacket();
        arp.hardtype = ARPPacket.HARDTYPE_ETHER;    //硬件类型
        arp.prototype = ARPPacket.PROTOTYPE_IP; //协议类型
        arp.operation = ARPPacket.ARP_REQUEST;  //表示是ARP请求包
        arp.hlen = 6;   //物理地址长度
        arp.plen = 4;   //协议地址长度
        arp.sender_hardaddr = DEVICE.mac_address; //ARP包的发送端以太网地址,在这里即本地主机MAC地址
        arp.sender_protoaddr = senderIP.getAddress(); //发送端IP地址, 在这里即本地IP地址

        //ARP数据字段中目标地址
        byte[] broadcast = new byte[]{(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255}; //广播地址
        arp.target_hardaddr = broadcast; //设置目的端的以太网地址为广播地址
        arp.target_protoaddr = targetIP.getAddress(); //目的端IP地址

        //构造以太网首部帧
        jpcap.packet.EthernetPacket ether = new jpcap.packet.EthernetPacket();
        ether.frametype = jpcap.packet.EthernetPacket.ETHERTYPE_ARP; //帧类型
        ether.src_mac = DEVICE.mac_address; //源MAC地址
        ether.dst_mac = broadcast; //以太网目的地址，广播地址
        arp.datalink = ether; //将arp报文的数据链路层的帧设置为刚刚构造的以太帧赋给

        //发送报文
        sender.sendPacket(arp); //发送ARP报文

        /**
         * 接收ARP回复
         */
        while(true){ //获取ARP回复包，从中提取出目的主机的MAC地址，如果返回的是网关地址，表明目的IP不是局域网内的地址
            Packet packet = jc.getPacket();
            if(packet instanceof ARPPacket){
                ARPPacket p=(ARPPacket)packet;
                if(p == null){
                    throw new IllegalArgumentException(targetIP+" is not a local address"); //这种情况也属于目的主机不是本地地址
                }
                if(Arrays.equals(p.target_protoaddr,senderIP.getAddress())){
                    System.out.println("------------ARP---------------");
                    System.out.println("Hardware type: " + p.hardtype);
                    System.out.println("Prototype type: " + p.prototype);
                    System.out.println("Opcode: " + p.operation);
                    System.out.println("Sender IP: " + macByteToString(p.sender_protoaddr));
                    System.out.println("Sender MAC: " +macByteToString(p.sender_hardaddr));
                    System.out.println("target IP: " +macByteToString(p.target_protoaddr));
                    System.out.println("target MAC: " +macByteToString(p.target_hardaddr));
                    System.out.println("------------ARP---------------");

                    return p.sender_hardaddr; //返回
                }
            }
        }

    }

    /**
     * 查询本地主机的IP还有MAC地址
     */
    public static void getLocalIPAndMAC() throws Exception{
            InetAddress inetAddress = InetAddress.getLocalHost();

            //获取本地IP
            String localName = inetAddress.getHostName();
            String localIP = inetAddress.getHostAddress();


        //根据网卡获取本机MAC地址
        byte[] mac = DEVICE.mac_address;

        LOCALIP = localIP;

        System.out.println("---------获取本机信息-----------");
        System.out.println("Local name：" + localName);
        System.out.println("Local IP：" + localIP);
        System.out.println("Local MAC：" + macByteToString(mac));
        System.out.println("---------获取本机信息结束-----------");
    }

    /**
     * 发送ICMP的PING命令，并且接收回送
     * @param ip
     * @param mac
     * @throws Exception
     */
    public static void ping(String ip, byte[] mac) throws Exception{

        //获取数据
        JpcapCaptor jc = JpcapCaptor.openDevice(DEVICE, 2000, false, 3000);//打开网络设备
        jc.setFilter("icmp", true);
        JpcapSender sender = jc.getJpcapSenderInstance();   // 用来发送报文的发送器
        InetAddress senderIP = InetAddress.getByName(LOCALIP);  //本地主机的IP
        InetAddress targetIP = InetAddress.getByName(ip);   //目标主机的IP

        //封装ICMP的帧
        ICMPPacket icmpPacket = new ICMPPacket();
        icmpPacket.type = ICMPPacket.ICMP_ECHO;
        icmpPacket.seq = (short) 0x0005;
        icmpPacket.id = (short) 0x0006;

        //封装IP的包
        icmpPacket.setIPv4Parameter(0,false,false,false,0,false,false,false,
                0,1010101,100, IPPacket.IPPROTO_ICMP,senderIP,targetIP);

        icmpPacket.data = "abcdefghijklmonpqrstuvwabcdehghi".getBytes();


        //构造以太网首部帧
        EthernetPacket ether = new EthernetPacket();
        ether.frametype = EthernetPacket.ETHERTYPE_IP; //帧类型
        ether.src_mac = DEVICE.mac_address; //源MAC地址
        ether.dst_mac = mac; //以太网目的地MAC 是网管MAC

        icmpPacket.datalink = ether; //将ICMP报文的数据链路层的帧设置为刚刚构造的以太帧赋给

        //发送ICMP的ECHO
        sender.sendPacket(icmpPacket);
        System.out.println("ping to " + icmpPacket.dst_ip + ".......");
        /**
         * 接收ICMP回复
         */
        ICMPPacket rp = null;

        while(true){
            rp = (ICMPPacket) jc.getPacket();
            if (null == rp){

                System.out.println("reply finish");

                return;
//                throw new IllegalArgumentException("no recieve ICMP echo reply");
            }else {
                System.out.println("---------ICMP---------");
                System.out.println("Type： " + rp.type);
                System.out.println("Code： " + rp.code);
                System.out.println("CheckSum： " + rp.checksum);
                System.out.println("Sequence： " + rp.seq);
                System.out.println("Id： " + rp.id);
                System.out.println("Data： " + macByteToString(rp.data));
                System.out.println("---------ICMP END---------");

                /**
                 * 输出到文件
                 */
                FileWriter writer = null;
                Date date = new Date();
                try {
                    // 打开一个写文件器，构造函数中的第二个参数true表示以追加形式写文件
                    writer = new FileWriter(FILEPATH, true);
                    writer.write("------------------" + date.toString() + "------------------" + System.getProperty("line.separator"));
                    writer.write("源IP： " + rp.src_ip + System.getProperty("line.separator"));
                    writer.write("目的IP： " + rp.dst_ip + System.getProperty("line.separator"));
                    writer.write("Data: " + macByteToString(rp.data) +  System.getProperty("line.separator"));
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    try {
                        if(writer != null){
                            writer.close();
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

            }

        }

    }


    public static void main(String[] args) throws Exception{
        getLocalIPAndMAC();
        getAllDevices();
        System.out.println("Enter Gateway IP");
        Scanner scanner = new Scanner(System.in);//输入网关IP
        String WangGuanIP = scanner.nextLine().toString();
        try{
            byte[] wangGuanMAC = getMACByIp(WangGuanIP);
            System.out.println("Enter Target IP");
            scanner = new Scanner(System.in);//输入目标IP
            String targetIP = scanner.nextLine().toString();
            ping(targetIP, wangGuanMAC);
        }catch (Exception e){
            System.out.println("IP ERROR");
            e.printStackTrace();
        }

    }
}
