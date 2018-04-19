package com.wchstrife.Packet;

import jpcap.packet.DatalinkPacket;
import jpcap.packet.IPPacket;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class ICMPPacket extends IPPacket {
    private static final long serialVersionUID = 1L;
    public static final short ICMP_ECHOREPLY = 0;
    public static final short ICMP_UNREACH = 3;
    public static final short ICMP_UNREACH_NET = 0;
    public static final short ICMP_UNREACH_HOST = 1;
    public static final short ICMP_UNREACH_PROTOCOL = 2;
    public static final short ICMP_UNREACH_PORT = 3;
    public static final short ICMP_UNREACH_NEEDFRAG = 4;
    public static final short ICMP_UNREACH_SRCFAIL = 5;
    public static final short ICMP_UNREACH_NET_UNKNOWN = 6;
    public static final short ICMP_UNREACH_HOST_UNKNOWN = 7;
    public static final short ICMP_UNREACH_ISOLATED = 8;
    public static final short ICMP_UNREACH_NET_PROHIB = 9;
    public static final short ICMP_UNREACH_HOST_PROHIB = 10;
    public static final short ICMP_UNREACH_TOSNET = 11;
    public static final short ICMP_UNREACH_TOSHOST = 12;
    public static final short ICMP_UNREACH_FILTER_PROHIB = 13;
    public static final short ICMP_UNREACH_HOST_PRECEDENCE = 14;
    public static final short ICMP_UNREACH_PRECEDENCE_CUTOFF = 15;
    public static final short ICMP_SOURCEQUENCH = 4;
    public static final short ICMP_REDIRECT = 5;
    public static final short ICMP_REDIRECT_NET = 0;
    public static final short ICMP_REDIRECT_HOST = 1;
    public static final short ICMP_REDIRECT_TOSNET = 2;
    public static final short ICMP_REDIRECT_TOSHOST = 3;
    public static final short ICMP_ECHO = 8;
    public static final short ICMP_ROUTERADVERT = 9;
    public static final short ICMP_ROUTERSOLICIT = 10;
    public static final short ICMP_TIMXCEED = 11;
    public static final short ICMP_TIMXCEED_INTRANS = 0;
    public static final short ICMP_TIMXCEED_REASS = 1;
    public static final short ICMP_PARAMPROB = 12;
    public static final short ICMP_PARAMPROB_ERRATPTR = 0;
    public static final short ICMP_PARAMPROB_OPTABSENT = 1;
    public static final short ICMP_PARAMPROB_LENGTH = 2;
    public static final short ICMP_TSTAMP = 13;
    public static final short ICMP_TSTAMPREPLY = 14;
    public static final short ICMP_IREQ = 15;
    public static final short ICMP_IREQREPLY = 16;
    public static final short ICMP_MASKREQ = 17;
    public static final short ICMP_MASKREPLY = 18;
    public byte type;
    public byte code;
    public short checksum;
    public short id;
    public short seq;
    public int subnetmask;
    public int orig_timestamp;
    public int recv_timestamp;
    public int trans_timestamp;
    public short mtu;
    public IPPacket ippacket;
    public InetAddress redir_ip;
    public byte addr_num;
    public byte addr_entry_size;
    public short alive_time;
    public InetAddress[] router_ip;
    public int[] preference;

    public ICMPPacket() {
    }

    void setValue(byte type, byte code, short checksum, short id, short seq) {
        this.type = type;
        this.code = code;
        this.checksum = checksum;
        this.id = id;
        this.seq = seq;
    }

    void setID(short id, short seq) {
        this.id = id;
        this.seq = seq;
    }

    void setTimestampValue(int orig, int recv, int trans) {
        this.orig_timestamp = orig;
        this.recv_timestamp = recv;
        this.trans_timestamp = trans;
    }

    void setRedirectIP(byte[] ip) {
        try {
            this.redir_ip = InetAddress.getByAddress(ip);
        } catch (UnknownHostException var3) {
            ;
        }

    }

    byte[] getRedirectIP() {
        return this.redir_ip.getAddress();
    }

    void setRouterAdValue(byte addr_num, byte entry_size, short alive_time, String[] addr, int[] pref) {
        this.addr_num = addr_num;
        this.addr_entry_size = entry_size;
        this.alive_time = alive_time;

        for(int i = 0; i < addr_num; ++i) {
            try {
                this.router_ip[i] = InetAddress.getByName(addr[i]);
            } catch (UnknownHostException var8) {
                ;
            }

            this.preference[i] = pref[i];
        }

    }

    public String toString() {
        return super.toString() + "type(" + this.type + ") code(" + this.code + ")";
    }
}
