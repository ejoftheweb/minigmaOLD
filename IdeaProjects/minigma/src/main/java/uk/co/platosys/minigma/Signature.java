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

public final class Signature {
    private PGPSignature pgpSignature;
    private String shortDigest;
    private long keyID;

    protected Signature (PGPSignature pgpSignature, String shortDigest){
        this.pgpSignature=pgpSignature;
        this.shortDigest=shortDigest;
    }
    public Signature (String string){

    }
    public Signature (InputStream inputStream){

    }
    public Signature (File file) throws Exception {
        this.shortDigest=file.getName();
        FileInputStream fileInputStream = new FileInputStream(file);
        ArmoredInputStream armoredInputStream = new ArmoredInputStream(fileInputStream);
        JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(armoredInputStream));
        PGPSignatureList signatureList;
        Object object = jcaPGPObjectFactory.nextObject();
        if (object instanceof PGPCompressedData){
            PGPCompressedData pgpCompressedData = (PGPCompressedData)object;
            jcaPGPObjectFactory = new JcaPGPObjectFactory(pgpCompressedData.getDataStream());
            Object object2 = jcaPGPObjectFactory.nextObject();
            if (object2 instanceof  PGPSignatureList){
                signatureList=(PGPSignatureList)object2;
            }else{
                throw new MinigmaException("unexpected object type found in compressed data signature stream");
            }
        }else if (object instanceof PGPSignatureList){
            signatureList=(PGPSignatureList) object;
        }else{
            throw new MinigmaException("unexpected object type found in uncompressed signature stream");
        }
        this.pgpSignature=signatureList.get(0);

    }

    /**
     * Returns the Signature as a String. The String representations don't have PGP Ascii Armor so aren't fully interoperable,
     * if you need Ascii Armor, use the following method with armored=true.
     * @return
     */
    public String encodeToString(){
      return encodeToString(false);
    }

    public String encodeToString(boolean armored){
        return MinigmaUtils.encode(encodeToBytes(armored));
    }
    protected byte[] encodeToBytes (boolean armored){
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            encodeToStream(byteArrayOutputStream, armored);
        }catch(Exception x){}
        byte[] signatureBytes=byteArrayOutputStream.toByteArray();
        return signatureBytes;
    }
    protected byte[] getBytes(){
        return encodeToBytes(false);
    }
    /**
     * Writes the signature to the given output stream, with or without PGP Ascii Armor headers/footers.
     * Use armored=false if interoperability isn't a concern.
     *
     * @param outputStream
     * @param armored
     * @throws IOException
     */
    public void encodeToStream(OutputStream outputStream, boolean armored) throws IOException{
        if(armored){
            encodeToStream(outputStream);
        }else{
            pgpSignature.encode(outputStream);
            outputStream.flush();
            outputStream.close();
        }
    }

    /**
     * Writes the signature to the given output stream in PGP AsciiArmored format. This maximises interoperability with
     * other OpenPGP implementations.
     * @param outputStream
     * @throws IOException
     */
    public void encodeToStream(OutputStream outputStream) throws IOException{
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream);
        pgpSignature.encode(armoredOutputStream);
        armoredOutputStream.flush();
        armoredOutputStream.close();
    }

    /**
     * Writes the signature to the given file in PGP Ascii Armored format. This maximises interoperability with
     * other OpenPGP implementations.
     * @param file
     * @throws IOException
     */
    public void encodeToFile(File file) throws  IOException{
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        encodeToStream(fileOutputStream);
        fileOutputStream.flush();
        fileOutputStream.close();
    }
    public String getShortDigest(){
        return shortDigest;
    }
    public long getKeyID(){
        return pgpSignature.getKeyID();
    }
}
