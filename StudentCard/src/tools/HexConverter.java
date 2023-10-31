package tools;

import java.util.Formatter;

public class HexConverter {
    public static String convert(byte[] data) {
        StringBuilder hexBuilder = new StringBuilder();
        try (Formatter formatter = new Formatter(hexBuilder)) {
            for(byte b: data) {
                formatter.format("%02X", b);
            }
        }
        String hexString = hexBuilder.toString();
        return hexString;
    }
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
