package main;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import apdu.APDU;
import apdu.List_of_apdus;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.encoders.Base64Encoder;
import services.CSR_Generation;
import services.Certificate;
import tools.HexConverter;

public class Main {
    public static void main(String[] args) throws Exception {
        APDU apdu = new APDU();
        apdu.connect();
        List_of_apdus list_of_apdus = new List_of_apdus();

        // Import certificate into smart card
        String filepath = "certc595d012155ac76fe02951a8b88db619060bd095.crt";
        Certificate certificate = new Certificate(apdu, list_of_apdus, filepath);
        certificate.importCert();

        // Export certificate from smart card
        byte[] certExport = certificate.exportCert();
        X509Certificate newCert = Certificate.convertCert(certExport);

        // Generate CSR file
		try {
			String subject = "CN=user,O=HUST,L=Test,C=VN";
			CSR_Generation generation = new CSR_Generation(apdu, list_of_apdus, subject);
			String csr = generation.genCSR(subject);
            String csr_file = "csr_file.csr";
            PrintWriter out = new PrintWriter(csr_file);
            out.println(csr);
            out.close();
            System.out.println(csr);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

        apdu.disConnect();
    }
}
