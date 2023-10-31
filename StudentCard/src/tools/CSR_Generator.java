package tools;

import apdu.APDU;
import apdu.List_of_apdus;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringWriter;
import java.security.PublicKey;

public class CSR_Generator {
    private APDU apdu;
    private List_of_apdus list_of_apdus;
    private CertificationRequestInfo info;

    public CSR_Generator(String x500Name, PublicKey publicKey) {
        X500Principal principal = new X500Principal(x500Name);
        X500Name subject = X500Name.getInstance(principal);
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey);
        info = new CertificationRequestInfo(subject, publicKeyInfo, new DERSet());
    }

    public byte[] getInfo() throws IOException {
        return info.getEncoded(ASN1Encoding.DER);
    }

    public String generateCSR(byte[] csrSignature) throws Exception {
        try {
            final AlgorithmIdentifier algorithm = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
            CertificationRequest certRequest = new CertificationRequest(info, algorithm, new DERBitString(csrSignature));
            PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(certRequest);
            return convertCertReqToPem(pkcs10CertificationRequest);
        } catch (IllegalArgumentException e) {
            throw new Exception("Signing Algorithms is invalid!");
        }
        catch (Exception e) {
            throw new Exception("Convert CSR to PEM failed!");
        }
    }

    private String convertCertReqToPem(final PKCS10CertificationRequest certRequest) throws IOException {
        final StringWriter writer = new StringWriter();
        final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(certRequest);
        pemWriter.flush();
        pemWriter.close();
        return writer.toString();
    }

    public byte[] getCertInfo() throws IOException {
        return info.getEncoded();
    }

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

    public void setInfo(CertificationRequestInfo info) {
        this.info = info;
    }

}
