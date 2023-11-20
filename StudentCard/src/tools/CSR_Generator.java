package tools;
import com.tencent.kona.sun.security.util.DerOutputStream;
import com.tencent.kona.sun.security.x509.AlgorithmId;
import com.tencent.kona.sun.security.x509.X500Name;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class CSR_Generator {
    public static byte[] createCertReqInfo(X500Name x500Name, PublicKey publicKey) throws IOException {
        final DerOutputStream der1 = new DerOutputStream();
        der1.putInteger(BigInteger.ZERO);
        x500Name.encode(der1);
        der1.write(publicKey.getEncoded());

        final DerOutputStream der2 = new DerOutputStream();
        der2.write((byte)48, der1);
        return der2.toByteArray();
    }

    public static byte[] createCertReqInfoValue(byte[] certReqInfo, String algorithm, byte[] signature)
            throws IOException, NoSuchAlgorithmException {
        final DerOutputStream der1 = new DerOutputStream();
        der1.write(certReqInfo);

        AlgorithmId.get(algorithm).encode(der1);
        der1.putBitString(signature);

        final DerOutputStream der2 = new DerOutputStream();
        der2.write((byte)48, der1);
        return der2.toByteArray();
    }
}
