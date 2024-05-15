package services;

import apdu.APDU;
import apdu.List_of_apdus;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import org.apache.logging.log4j.core.util.FileUtils;
import tools.HexConverter;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.X509Certificate;

import com.itextpdf.kernel.pdf.PdfReader;

public class Signature {
    private Certification certification;
    public Signature(Certification certification) {
        this.certification = certification;
    }

    public void signPdfFile(String src_path, X509Certificate certificate,
                            String reason, String location) throws IOException, GeneralSecurityException {
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = certificate;

        PdfReader reader = new PdfReader(src_path);
        File source = new File(src_path);
        StringBuilder str = new StringBuilder(src_path);
        String tmp = str.substring(0, src_path.length() - 4);
        String dest_path = tmp + "_signed.pdf";
        File dest = new File(dest_path);
        Files.copy(source.toPath(), dest.toPath());
        FileOutputStream os = new FileOutputStream(dest_path);
        PdfSigner signer = new PdfSigner(reader, os, new StampingProperties());

        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setPageRect(new Rectangle(38, 648, 200, 100));
        appearance.setPageNumber(1);

        IExternalSignature signature = new IExternalSignature() {
            @Override
            public String getHashAlgorithm() {
                return DigestAlgorithms.SHA256;
            }
            @Override
            public String getEncryptionAlgorithm() {
                return "RSA";
            }
            @Override
            public byte[] sign(byte[] message) throws GeneralSecurityException {
                return signBytes(message);
            }
        };
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, signature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
    }

    public byte[] signBytes(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        APDU apdu = certification.apdu;
        List_of_apdus list_of_apdus = certification.list_of_apdus;
        // Sign data
        apdu.selectApplet(list_of_apdus.getCsr_system());
        String response = apdu.sendData((byte)0x00, (byte)0x03, (byte)0x01, (byte)0x02, data, false);
        byte[] signed = HexConverter.hexStringToByteArray(response);
        return signed;
    }

    public byte[] signString(String string) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        APDU apdu = certification.apdu;
        List_of_apdus list_of_apdus = certification.list_of_apdus;
        byte[] data = string.getBytes();
        System.out.println(HexConverter.convert(data));

        // Sign data
        apdu.selectApplet(list_of_apdus.getCsr_system());
        String response = apdu.sendData((byte)0x00, (byte)0x03, (byte)0x01, (byte)0x02, data, false);
        byte[] signed = HexConverter.hexStringToByteArray(response);
        return signed;
    }
    public boolean verifyString(String string, byte[] signed) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        byte[] data = string.getBytes();
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initVerify(certification.certificate.getPublicKey());
        sig.update(data);
        return sig.verify(signed);
    }
}


