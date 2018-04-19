package com.wchstrife.Packet;

import jpcap.packet.DatalinkPacket;

public class EthernetPacket extends DatalinkPacket {
    private static final long serialVersionUID = 1L;

    public byte[] dst_mac;
    public byte[] src_mac;
    public short frametype;
    public static final short ETHERTYPE_PUP = 512;
    public static final short ETHERTYPE_IP = 2048;
    public static final short ETHERTYPE_ARP = 2054;
    public static final short ETHERTYPE_REVARP = -32715;
    public static final short ETHERTYPE_VLAN = -32512;
    public static final short ETHERTYPE_IPV6 = -31011;
    public static final short ETHERTYPE_LOOPBACK = -28672;

    public EthernetPacket() {
    }

    void setValue(byte[] dst, byte[] src, short frame) {
        this.dst_mac = dst;
        this.src_mac = src;
        this.frametype = frame;
    }

    public String getSourceAddress() {
        char[] src = new char[17];

        for(int i = 0; i < 5; ++i) {
            src[i * 3] = this.hexUpperChar(this.src_mac[i]);
            src[i * 3 + 1] = this.hexLowerChar(this.src_mac[i]);
            src[i * 3 + 2] = ':';
        }

        src[15] = this.hexUpperChar(this.src_mac[5]);
        src[16] = this.hexLowerChar(this.src_mac[5]);
        return new String(src);
    }

    public String getDestinationAddress() {
        char[] dst = new char[17];

        for(int i = 0; i < 5; ++i) {
            dst[i * 3] = this.hexUpperChar(this.dst_mac[i]);
            dst[i * 3 + 1] = this.hexLowerChar(this.dst_mac[i]);
            dst[i * 3 + 2] = ':';
        }

        dst[15] = this.hexUpperChar(this.dst_mac[5]);
        dst[16] = this.hexLowerChar(this.dst_mac[5]);
        return new String(dst);
    }

    public String toString() {
        return super.toString() + " " + this.getSourceAddress() + "->" + this.getDestinationAddress() + " (" + this.frametype + ")";
    }

    private char hexUpperChar(byte b) {
        b = (byte)(b >> 4 & 15);
        if (b == 0) {
            return '0';
        } else {
            return b < 10 ? (char)(48 + b) : (char)(97 + b - 10);
        }
    }

    private char hexLowerChar(byte b) {
        b = (byte)(b & 15);
        if (b == 0) {
            return '0';
        } else {
            return b < 10 ? (char)(48 + b) : (char)(97 + b - 10);
        }
    }
}
