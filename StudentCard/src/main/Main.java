package main;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import apdu.APDU;
import apdu.List_of_apdus;
import services.CSR_Generation;

public class Main {
    public static void main(String[] args) throws Exception {
        APDU apdu = new APDU();
        apdu.connect();
        List_of_apdus list_of_apdus = new List_of_apdus();

		try {
			String subject = "CN=test_user,O=HUST,L=Test,C=VN";
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
