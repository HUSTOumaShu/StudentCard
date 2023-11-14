package tools;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash {
    public String hash(String text) {
        byte[] hash = new byte[] {};
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return HexConverter.convert(hash);
    }

    public static byte[] hash(byte[] data) throws NoSuchAlgorithmException {
        byte[] hash = new byte[] {};
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        hash = digest.digest(data);
        return hash;
    }
}