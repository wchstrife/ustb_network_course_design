package com.wchstrife.Packet;

import jpcap.packet.Packet;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class ARPPacket extends Packet {
    private static final long serialVersionUID = 1L;

    public short hardtype;
    public static final short HARDTYPE_ETHER = 1;
    public static final short HARDTYPE_IEEE802 = 6;
    public static final short HARDTYPE_FRAMERELAY = 15;
    public short prototype;
    public static final short PROTOTYPE_IP = 2048;
    public short hlen;
    public short plen;
    public short operation;
    public static final short ARP_REQUEST = 1;
    public static final short ARP_REPLY = 2;
    public static final short RARP_REQUEST = 3;
    public static final short RARP_REPLY = 4;
    public static final short INV_REQUEST = 8;
    public static final short INV_REPLY = 9;
    public byte[] sender_hardaddr;
    public byte[] sender_protoaddr;
    public byte[] target_hardaddr;
    public byte[] target_protoaddr;

    public ARPPacket() {
    }

    void setValue(short hardtype, short prototype, short hlen, short plen, short operation, byte[] sha, byte[] spa, byte[] tha, byte[] tpa) {
        this.hardtype = hardtype;
        this.prototype = prototype;
        this.hlen = hlen;
        this.plen = plen;
        this.operation = operation;
        this.sender_hardaddr = sha;
        this.sender_protoaddr = spa;
        this.target_hardaddr = tha;
        this.target_protoaddr = tpa;
    }

    public Object getSenderHardwareAddress() {
        switch(this.hardtype) {
            case 1:
                char[] adr = new char[17];

                for(int i = 0; i < 5; ++i) {
                    adr[i * 3] = this.hexUpperChar(this.sender_hardaddr[i]);
                    adr[i * 3 + 1] = this.hexLowerChar(this.sender_hardaddr[i]);
                    adr[i * 3 + 2] = ':';
                }

                adr[15] = this.hexUpperChar(this.sender_hardaddr[5]);
                adr[16] = this.hexLowerChar(this.sender_hardaddr[5]);
                return new String(adr);
            default:
                return "Unknown Protocol";
        }
    }

    public Object getTargetHardwareAddress() {
        switch(this.hardtype) {
            case 1:
                char[] adr = new char[17];

                for(int i = 0; i < 5; ++i) {
                    adr[i * 3] = this.hexUpperChar(this.target_hardaddr[i]);
                    adr[i * 3 + 1] = this.hexLowerChar(this.target_hardaddr[i]);
                    adr[i * 3 + 2] = ':';
                }

                adr[15] = this.hexUpperChar(this.target_hardaddr[5]);
                adr[16] = this.hexLowerChar(this.target_hardaddr[5]);
                return new String(adr);
            default:
                return "Unknown Protocol";
        }
    }

    public Object getSenderProtocolAddress() {
        switch(this.prototype) {
            case 2048:
                try {
                    return InetAddress.getByAddress(this.sender_protoaddr);
                } catch (UnknownHostException var2) {
                    return "Unknown Address";
                }
            default:
                return "Unknown Protocol";
        }
    }

    public Object getTargetProtocolAddress() {
        switch(this.prototype) {
            case 2048:
                try {
                    return InetAddress.getByAddress(this.target_protoaddr);
                } catch (UnknownHostException var2) {
                    return "Unknown Address";
                }
            default:
                return "Unknown Protocol";
        }
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        switch(this.operation) {
            case 1:
                buf.append("ARP REQUEST ");
                break;
            case 2:
                buf.append("ARP REPLY ");
                break;
            case 3:
                buf.append("RARP REQUEST ");
                break;
            case 4:
                buf.append("RARP REPLY ");
                break;
            case 5:
            case 6:
            case 7:
            default:
                buf.append("UNKNOWN ");
                break;
            case 8:
                buf.append("IDENTIFY REQUEST ");
                break;
            case 9:
                buf.append("IDENTIFY REPLY ");
        }

        return buf.toString() + this.getSenderHardwareAddress() + "(" + this.getSenderProtocolAddress() + ") -> " + this.getTargetHardwareAddress() + "(" + this.getTargetProtocolAddress() + ")";
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
