package uk.co.platosys.minigma;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import uk.co.platosys.minigma.exceptions.MinigmaException;

import java.io.InputStream;

public abstract class BaseSignature {
    protected PGPSignature pgpSignature;
    protected String shortDigest;

    protected BaseSignature (PGPSignature pgpSignature, String shortDigest){
        this.pgpSignature=pgpSignature;
        this.shortDigest=shortDigest;
    }
    protected BaseSignature (String string){

    }
    protected BaseSignature (InputStream inputStream){
        PGPSignatureList signatureList;
        try {
            this.shortDigest = shortDigest;
            ArmoredInputStream armoredInputStream = new ArmoredInputStream(inputStream);
            JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(armoredInputStream));
            Object object = jcaPGPObjectFactory.nextObject();
            if (object instanceof PGPCompressedData) {
                PGPCompressedData pgpCompressedData = (PGPCompressedData) object;
                jcaPGPObjectFactory = new JcaPGPObjectFactory(pgpCompressedData.getDataStream());
                Object object2 = jcaPGPObjectFactory.nextObject();
                if (object2 instanceof PGPSignatureList) {
                    signatureList = (PGPSignatureList) object2;
                } else {
                    throw new MinigmaException("unexpected object type found in compressed data signature stream");
                }
            } else if (object instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) object;
            } else {
                throw new MinigmaException("unexpected object type found in uncompressed signature stream");
            }
            this.pgpSignature=signatureList.get(0);
        }catch(Exception x){

        }
    }
}
