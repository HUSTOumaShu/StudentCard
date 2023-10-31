package services;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import apdu.APDU;
import apdu.List_of_apdus;
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
        byte[] certInfo = generator.getCertInfo();
        byte[] certHash = new Hash().hash(certInfo);
        byte[] certSign = signData(certHash);
        String csr = generator.generateCSR(certSign);
        return csr;
    }

    /*
     * Method with card
     */
    public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {
        apdu.selectApplet(list_of_apdus.getCsr_system());
        String response = apdu.sendData((byte)0x00, (byte)0x03, (byte)0x01, (byte)0x02, new byte[] {}, false);
        StringBuilder sb = new StringBuilder(response);
        String exponent_str = sb.substring(4,10);
        String modulus_str = sb.substring(14);
        BigInteger exponent  = new BigInteger(exponent_str);
        BigInteger modulus = new BigInteger(modulus_str, 16);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(spec);

        return publicKey;
    }

    public byte[] signData(byte[] data) {
        apdu.selectApplet(list_of_apdus.getCsr_system());
        String response = apdu.sendData((byte)0x00, (byte)0x01, (byte)0x01, (byte)0x02, data, false);
        new HexConverter();
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
