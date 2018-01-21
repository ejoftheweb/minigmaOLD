package uk.co.platosys.minigma;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.utils.MinigmaUtils;

import java.io.*;

/**
 * The Signature object  wraps a BouncyCastle PGPSignature object.
 * It can be instantiated from a String, an InputStream or a File.
 * It is often just a list of size 1, containing a single signature.
 *
 *
 *
 */

public  final class Signature extends BaseSignature {

    private long keyID;

    protected Signature (PGPSignature pgpSignature, String signerUserID){
        super(pgpSignature, signerUserID);
    }
    public Signature (String string){
        super(string);
    }
    public Signature (InputStream inputStream, String shortDigest){
       super(inputStream);

    }
    public Signature (File file) throws Exception {
        this( new FileInputStream(file), file.getName());
    }


}
