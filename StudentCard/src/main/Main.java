package main;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import apdu.APDU;
import apdu.List_of_apdus;
import services.CSR_Generation;
import tools.HexConverter;

public class Main {
    public static void main(String[] args) throws Exception {
        APDU apdu = new APDU();
        apdu.connect();
        List_of_apdus list_of_apdus = new List_of_apdus();

        // Generate new key pair
        apdu.selectApplet(list_of_apdus.getCsr_system());
        apdu.sendData((byte)0x00, (byte)0x00, (byte)0x01, (byte)0x02, new byte[] {}, false);

        // Sign
//        apdu.selectApplet(list_of_apdus.getCsr_system());
//        apdu.sendData((byte)0x00, (byte)0x01, (byte)0x01, (byte)0x02, new byte[] {0x20,0x20,0x47,0x57}, true);

		try {
			String subject = "CN=username,O=Test,L=Test,C=VN";
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

        /*
         * Verify user via password
         */
//		Verify verify = new Verify(apdu, list_of_apdus);
//		boolean check = verify.verify();
//		if(check) System.out.println("Access success..");
//		else System.out.println("Invalid information!!");

//		// send data and receive data
//		apdu.selectApplet(list_of_apdus.getService_sendData());
//		apdu.sendData((byte)0x00, (byte)0x00, (byte)0x01, (byte)0x02, new byte[] {0x20, 0x20, 0x47, 0x57}, true);
//
//		// send data and receive data after encrypted
//		apdu.selectApplet(list_of_apdus.getService_cryptoData());
//		apdu.sendData((byte)0x00, (byte)0x00, (byte)0x01, (byte)0x02, new byte[] {0x20, 0x20, 0x47, 0x57}, true);
//		apdu.sendData((byte)0x00, (byte)0x01, (byte)0x01, (byte)0x02, "C610AFFA30D84AA9FCB65302F69BBCCC", true);
//
//		// generate random data
//		apdu.selectApplet(list_of_apdus.getService_genRandom());
//		apdu.sendData((byte)0x00, (byte)0x00, (byte)0x01, (byte)0x02, new byte[] {0x20, 0x20, 0x47, 0x57}, true);

//		/*
//		 * TGP System
//		 */
//		apdu.selectApplet(list_of_apdus.getTgp_system());
//		// Sign
//		apdu.sendData((byte)0x00, (byte)0x00, (byte)0x01, (byte)0x02, new byte[] {0x20, 0x20, 0x47, 0x57}, true);
//		// Verify and receive random key
//		apdu.sendData((byte)0x00, (byte)0x01, (byte)0x01, (byte)0x02, new byte[] {0x20, 0x20, 0x47, 0x57}, true);
//		// Connect to server1 to get key
//		System.out.println("Connect to Server and get the random key: ");
//		apdu.selectApplet(list_of_apdus.getTgp_server1());
//		apdu.sendData((byte)0x00, (byte)0x00, (byte)0x01, (byte)0x02, new byte[] {}, true);



        apdu.disConnect();
    }
}
