package com.wchstrife.Util;

public class Utils {

    /**
     * 将字符串形式的MAC地址转换成存放在byte数组内的MAC地址
     * @param str 字符串形式的MAC地址，如：AA-AA-AA-AA-AA
     * @return 保存在byte数组内的MAC地址
     */
    public static byte[] macStringToByte(String str) {
        byte[] mac = new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
        String[] temp = str.split("-");
        for (int x = 0; x < temp.length; x++) {
            mac[x] = (byte) ((Integer.parseInt(temp[x], 16)) & 0xff);
        }
        return mac;
    }

    public static String macByteToString(byte[] mac){

        StringBuffer sb = new StringBuffer();

        for (int i=0; i<mac.length; i++){
            if (i != 0){
                sb.append("-");
            }

            //mac[i] & 0xFF 是为了把byte转化为正整数
            String s = Integer.toHexString(mac[i] & 0xFF);
            sb.append(s.length()==1?0+s:s);
        }

        return sb.toString().toUpperCase();
    }
}
