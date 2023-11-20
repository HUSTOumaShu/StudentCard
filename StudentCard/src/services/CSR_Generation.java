package services;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

import apdu.APDU;
import apdu.List_of_apdus;
import com.tencent.kona.sun.security.x509.X500Name;
import tools.CSR_Generator;
import tools.HexConverter;

public class CSR_Generation {
    private APDU apdu;
    private List_of_apdus list_of_apdus;

    public CSR_Generation(APDU apdu, List_of_apdus list_of_apdus) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        this.apdu = apdu;
        this.list_of_apdus = list_of_apdus;
    }

    public String genCSR(String subject) throws Exception {
        X500Name x500Name = new X500Name(subject);
        byte[] certReqInfo = CSR_Generator.createCertReqInfo(x500Name, getPublicKey());

        String algorithms = "SHA256WithRSA";
        byte[] certReqSignature = signData(certReqInfo);

        byte[] csrDEREncoded = CSR_Generator.createCertReqInfoValue(certReqInfo, algorithms, certReqSignature);
        String csrPEMFormat = createPEMFormat(csrDEREncoded);

        writeToFile(csrDEREncoded, "csr.der");
        writeToFile(csrPEMFormat.getBytes(), "csr.csr");

        return HexConverter.convert(csrDEREncoded);
    }

    public static String createPEMFormat(byte[] data) {
        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        final PrintStream ps = new PrintStream(os);
        ps.println("-----BEGIN CERTIFICATE REQUEST-----");
        ps.println(Base64.getMimeEncoder().encodeToString(data));
        ps.println("-----END CERTIFICATE REQUEST-----");
        return os.toString();
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

    public static void writeToFile(byte[] data, String file) throws IOException {
        FileOutputStream os = new FileOutputStream(file);
        os.write(data);
    }
}
