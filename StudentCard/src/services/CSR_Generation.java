package services;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

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
        byte[] certHash = Hash.hash(certInfo);          // Hash CSR Request Info with SHA256
        byte[] certSign = signData(certHash);           // Sign with card
        String csr = generator.generateCSR(certSign);   // Convert to string

        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(getPublicKey());
        sig.update(certHash);
        boolean ret = sig.verify(certSign);
        System.out.println(HexConverter.convert(certSign));
        System.out.println(ret);

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

        System.out.println(res_mod);

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
