package services;

import java.util.Scanner;

import apdu.APDU;
import apdu.List_of_apdus;
import tools.Hash;

public class Verify {
	private String password;
	private APDU apdu;
	List_of_apdus list_of_apdus = new List_of_apdus();
	
	public Verify(APDU apdu, List_of_apdus list_of_apdus) {
		this.apdu = apdu;
		this.list_of_apdus = list_of_apdus;
	}
	
	public boolean verify() {
		// Enter the password
		Scanner scanner = new Scanner(System.in);
		System.out.println("Access your PIN: ");
		this.password = scanner.nextLine();
		
		// hash password 16 times
		String hash = new Hash().hash(password);
		for(int i = 0; i < 15; i++) {
			hash = new Hash().hash(hash);
		}
		System.out.println(hash);
		apdu.selectApplet(list_of_apdus.getService_verify());
		String response = apdu.sendData((byte)0x00, (byte)0x00, (byte)0x01, (byte)0x02, hash, true);
		scanner.close();
		if(response.equals("01")) return true;
		else return false;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
	
}
