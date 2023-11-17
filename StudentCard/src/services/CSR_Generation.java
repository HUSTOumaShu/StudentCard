package services;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import apdu.APDU;
import apdu.List_of_apdus;
import org.bouncycastle.util.encoders.Hex;
import tools.CSR_Generator;
import tools.Hash;
import tools.HexConverter;

public class CSR_Generation {
    private APDU apdu;
    private List_of_apdus list_of_apdus;
    private CSR_Generator generator;
    private String x500Name;

    public CSR_Generation(APDU apdu, List_of_apdus list_of_apdus, String x500Name) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        this.apdu = apdu;
        this.list_of_apdus = list_of_apdus;
        this.x500Name = x500Name;
        generator = new CSR_Generator(x500Name, getPublicKey());
    }

    public String genCSR(String subject) throws Exception {
        byte[] certInfo = generator.getCertInfo();      // generate CSR Request Info
        byte[] certSign = signData(certInfo);           // Sign with card
        String csr = generator.generateCSR(certSign);   // Convert to string

        return csr;
    }

    public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {
        apdu.selectApplet(list_of_apdus.getCsr_system());

        // Get exponent of public key
        String res_exp = apdu.sendData((byte)0x00, (byte)0x04, (byte)0x01, (byte)0x02, new byte[] {}, false);
        BigInteger exponent = new BigInteger(res_exp, 16);

        // Get modulus of public key
        String res_mod_start = apdu.sendData((byte)0x00, (byte)0x05, (byte)0x01, (byte)0x02, new byte[] {}, false);
        String res_mod_end = apdu.sendData((byte)0x00, (byte)0x06, (byte)0x01, (byte)0x02, new byte[] {}, false);
        String res_mod = res_mod_start + res_mod_end;
        BigInteger modulus = new BigInteger(res_mod, 16);

        // Restore public key from exponent and modulus
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(spec);

        return publicKey;
    }

    public byte[] signData(byte[] data) {
        // Send length of data for signing
        int certLenTmp = data.length;
        byte[] certLen = BigInteger.valueOf(certLenTmp).toByteArray();
        apdu.selectApplet(list_of_apdus.getCsr_system());
        apdu.sendData((byte)0x00, (byte)0x10, (byte)0x01, (byte)0x02, certLen, false);

        // Send data
        byte[] data_start = Arrays.copyOfRange(data, 0, 255);
        byte[] data_end = Arrays.copyOfRange(data, 255, data.length);
        apdu.sendData((byte)0x00, (byte)0x11, (byte)0x01, (byte)0x02, data_start, false);
        apdu.sendData((byte)0x00, (byte)0x12, (byte)0x01, (byte)0x02, data_end, false);

        // Sign data
        String response = apdu.sendData((byte)0x00, (byte)0x01, (byte)0x01, (byte)0x02, new byte[] {}, false);
        return HexConverter.hexStringToByteArray(response);
    }

    /*
     * Getter & Setter
     */
    public APDU getApdu() {
        return apdu;
    }

    public void setApdu(APDU apdu) {
        this.apdu = apdu;
    }

    public List_of_apdus getList_of_apdus() {
        return list_of_apdus;
    }

    public void setList_of_apdus(List_of_apdus list_of_apdus) {
        this.list_of_apdus = list_of_apdus;
    }

    public CSR_Generator getGenerator() {
        return generator;
    }

    public void setGenerator(CSR_Generator generator) {
        this.generator = generator;
    }

}
