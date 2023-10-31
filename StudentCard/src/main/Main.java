package main;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import apdu.APDU;
import apdu.List_of_apdus;
//import services.Verify;
import services.CSR_Generation;

public class Main {
    public static void main(String[] args) throws Exception {
        APDU apdu = new APDU();
        apdu.connect();
        List_of_apdus list_of_apdus = new List_of_apdus();

        apdu.selectApplet(list_of_apdus.getCsr_system());
        String response = apdu.sendData((byte)0x00, (byte)0x03, (byte)0x01, (byte)0x02, new byte[] {}, false);
        System.out.println(response);
//		try {
//			String subject = "CN=Test,OU=Test,O=Test,S=Test,C=Test";
//			CSR_Generation generation = new CSR_Generation(apdu, list_of_apdus);
//			byte[] csr = generation.genCSR(subject);
//			System.out.println(csr.toString());
//		} catch (NoSuchAlgorithmException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (InvalidKeySpecException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}

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
