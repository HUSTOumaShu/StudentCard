package main;


import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import apdu.APDU;
import apdu.List_of_apdus;
import services.CSR_Generation;
import services.Certification;
import services.Signature;
import tools.HexConverter;

public class Main {
    public static void main(String[] args) throws Exception {
        APDU apdu = new APDU();
        apdu.connect();
        List_of_apdus list_of_apdus = new List_of_apdus();

        // Generate CSR
//        genKey(apdu, list_of_apdus);
//        generateCSR(apdu, list_of_apdus);

        // Import certificate into smart card
//        String filepath = "hustshu2.der";
//        Certification certificate = new Certification(apdu, list_of_apdus, filepath);
//        certificate.importCert();

        // Export certificate from smart card
        Certification certification = new Certification(apdu, list_of_apdus);
        byte[] certExport = certification.exportCert();
        X509Certificate newCert = Certification.convertCert(certExport);
        certification.setCertificate(newCert);

        Signature signature = new Signature(certification);
//        signature.signString("Hello World!");

        String reason = "I want to sign!";
        String location = "Ha Noi";
        signature.signPdfFile("sample.pdf", "sample_signed.pdf", certification.getCertificate(), reason, location);
        apdu.disConnect();
    }
    public static void genKey(APDU apdu, List_of_apdus list_of_apdus) {
        apdu.selectApplet(list_of_apdus.getCsr_system());
        apdu.sendData((byte)0x00, (byte)0x00, (byte)0x01, (byte)0x02, new byte[] {}, false);
    }
    public static void generateCSR(APDU apdu, List_of_apdus list_of_apdus) {
        try {
            String subject = "CN=hustshu2,O=SOICT,L=HUST,C=VN";
            CSR_Generation generation = new CSR_Generation(apdu, list_of_apdus);
            String csr = generation.genCSR(subject);
            System.out.println(csr);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
