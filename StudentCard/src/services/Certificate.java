package services;

import apdu.APDU;
import apdu.List_of_apdus;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.util.encoders.Hex;
import tools.HexConverter;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class Certificate {
    private APDU apdu;
    private List_of_apdus list_of_apdus;
    X509Certificate certificate;

    public Certificate(APDU apdu, List_of_apdus list_of_apdus, String filepath) throws CertificateException, FileNotFoundException {
        this.apdu = apdu;
        this.list_of_apdus = list_of_apdus;
        CertificateFactory fac = CertificateFactory.getInstance("X509");
        FileInputStream file = new FileInputStream(filepath);
        this.certificate = (X509Certificate)(fac.generateCertificate(file));
    }

    public int importCert() throws FileNotFoundException, CertificateException {
        // Get certificate bytes array
        byte[] certificate = convertBytes();
        int certLenTmp = certificate.length;
        byte[] certLen = BigInteger.valueOf(certLenTmp).toByteArray();

        apdu.selectApplet(list_of_apdus.getCertificate());

        // Send length of certificate
        apdu.sendData((byte)0x00, (byte)0x00, (byte)0x01, (byte)0x02, certLen, false);

        // Split certificate into apdus with 256 bytes (5 bytes header + 1 byte index + 250 bytes data) and send
        int num = certLenTmp/250;
        boolean isDevided = (num*250 == certLenTmp);
        if(!isDevided) num++;
        for(int i = 0; i< num-1; i++) {
            byte index = (byte)i;
            byte[] data = Arrays.copyOfRange(certificate, i*250, i*250 + 250);
            byte[] packet = new byte[251];
            packet[0] = index;
            System.arraycopy(data, 0, packet, 1, 250);
            apdu.sendData((byte)0x00, (byte)0x01, (byte)0x01, (byte)0x02, packet, false);
        }

        // Process final package
        int length = certLenTmp - (num-1)*250;
        byte[] data = Arrays.copyOfRange(certificate, (num-1)*250, (num-1)*250 + length);
        byte[] packet = new byte[length+1];
        packet[0] = (byte)(num-1);
        System.arraycopy(data, 0, packet, 1, length);
        apdu.sendData((byte)0x00, (byte)0x01, (byte)0x01, (byte)0x02, packet, false);

        return num; // return the number of apdus sent
    }

    public byte[] exportCert() {
        apdu.selectApplet(list_of_apdus.getCertificate());

        // Get the length of Certificate in smart card
        String certLenTmp = apdu.sendData((byte)0x00, (byte)0x10, (byte)0x01, (byte)0x02, new byte[] {}, false);
        byte[] certLenBytes = HexConverter.hexStringToByteArray(certLenTmp);
        int certLen = (int)(certLenBytes[0])*256 + (int)(certLenBytes[1]);
        byte[] certificate = new byte[certLen];

        // Get the number of packages
        int numOfPack = certLen/250;
        boolean isDevided = (numOfPack*250 == certLen);
        if(!isDevided) numOfPack++;

        // Get the data of packages and combine to certificate
        for(int i = 0; i< numOfPack; i++) {
            byte index = (byte)i;
            String data_str = apdu.sendData((byte)0x00, (byte)0x11, (byte)0x01, (byte)0x02, new byte[] {index}, false);
            byte[] data = HexConverter.hexStringToByteArray(data_str);
            System.arraycopy(data, 0, certificate, (i*250), data.length);
        }
        return certificate;
    }

    public byte[] convertBytes() throws FileNotFoundException, CertificateException {
        return certificate.getEncoded();
    }

    public static X509Certificate convertCert(byte[] certBytes) throws CertificateException {
        CertificateFactory fac = CertificateFactory.getInstance("X509");
        X509Certificate cert = (X509Certificate)(fac.generateCertificate(new ByteArrayInputStream(certBytes)));
        return cert;
    }
}
