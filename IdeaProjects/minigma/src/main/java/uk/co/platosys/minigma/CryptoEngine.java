
package uk.co.platosys.minigma;



import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import uk.co.platosys.minigma.Key;
import uk.co.platosys.minigma.Lock;
import uk.co.platosys.minigma.Minigma;
import uk.co.platosys.minigma.exceptions.DecryptionException;
import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.exceptions.NoDecryptionKeyException;
import uk.co.platosys.minigma.utils.Kidney;
import uk.co.platosys.minigma.utils.MinigmaUtils;


/**
 * this  class holds the static decrypt and encrypt methods
 *
 * @author edward
 */
public  class CryptoEngine {
    private static String TAG ="CryptoEngine";

    /**
     *  Decrypts an InputStream to a byte array
     *
     * @param inputStream
     * @param key
     * @param passphrase
     * @return
     * @throws Exception
     */

    public static byte[] decrypt(InputStream inputStream, Key key, char[] passphrase)
            throws  MinigmaException,
                    DecryptionException,
                    java.io.IOException {
        InputStream decoderStream;
        PGPObjectFactory pgpObjectFactory=null;
        PGPEncryptedDataList pgpEncryptedDataList = null;
        try {
            decoderStream = PGPUtil.getDecoderStream(inputStream);
            pgpObjectFactory = new PGPObjectFactory(decoderStream, new JcaKeyFingerprintCalculator());
            boolean moreObjects=true;
            while (moreObjects) {
                Object object = pgpObjectFactory.nextObject();
                if (object == null) {
                    moreObjects = false;
                }
                if (object instanceof PGPEncryptedDataList) {
                    pgpEncryptedDataList = (PGPEncryptedDataList) object;
                    return decompress(decrypt(pgpEncryptedDataList, key, passphrase));
                } else {
                    System.out.println(object.getClass().getName());
                }
            }
            throw new MinigmaException("couldn't find encrypted data list");
        }catch (Exception e){
            Exceptions.dump(e);
            throw new MinigmaException("error reading encrypted data list", e);
        }
    }

    /**
     * An encryptedDataList will contain one or more blocks of encrypted data, usually the same literal data encrypted
     * to one or more public keys. Typically, the provided Key will only be able to unlock one of them.
     * @param pgpEncryptedDataList
     * @param key
     * @param passphrase
     * @return
     * @throws MinigmaException
     * @throws DecryptionException
     */
    private static PGPCompressedData decrypt(PGPEncryptedDataList pgpEncryptedDataList, Key key, char[] passphrase) throws MinigmaException, DecryptionException {
        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData pgpPublicKeyEncryptedData = null;
         try {
            Iterator<PGPPublicKeyEncryptedData> it = pgpEncryptedDataList.getEncryptedDataObjects();
            JcePBESecretKeyDecryptorBuilder keyDecryptorBuilder = new JcePBESecretKeyDecryptorBuilder();
            keyDecryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            int size  = pgpEncryptedDataList.size();
            int count = 0;
            while (it.hasNext() && privateKey == null) {
                pgpPublicKeyEncryptedData = it.next();
                count++;
                System.out.println();
                long keyID = pgpPublicKeyEncryptedData.getKeyID();
                //System.out.println("EncryptedDataBlock was encrypted with keyID "+Kidney.toString(keyID));
                try {
                    PGPSecretKey secretKey = key.getDecryptionKey(keyID);
                    if (secretKey.getKeyID() == keyID) {
                        privateKey = key.getDecryptionKey(keyID).extractPrivateKey(keyDecryptorBuilder.build(passphrase));
                        //System.out.println("Key match for "+Kidney.toString(keyID));
                    }
                } catch (NoDecryptionKeyException ndke) {
                    //System.out.println("no decryption key available for keyID "+Kidney.toString(keyID));
                    //we don't need to worry about this exception here.
                } catch (Exception x) {
                    System.out.println("oops exception in decrypt while loop");
                    Exceptions.dump(x);
                    throw new MinigmaException("CryptoEngine: getEncryptedDataObjects - unexpected exception", x);
                }
            }
            if (privateKey == null) {
                //System.out.println("Done "+ count + "keys of "+size+" altogether, still no private key");
                throw new DecryptionException("CryptoEngine: decryption key doesn't fit any of the locks");
            }
        } catch (DecryptionException dx) { //don't think this is ever thrown here
            Exceptions.dump(dx);
            throw dx;
        } catch (Exception e) {
             Exceptions.dump(e);
            throw new MinigmaException("A problem arose during decryption", e);
        }
        //so we now have an encrypted data object and a key that fits it...
        try {
            PublicKeyDataDecryptorFactory dataDecryptorFactory = new BcPublicKeyDataDecryptorFactory(privateKey);
            InputStream decryptedStream = pgpPublicKeyEncryptedData.getDataStream(dataDecryptorFactory);
            JcaPGPObjectFactory compressedFactory = new JcaPGPObjectFactory(decryptedStream);
            return (PGPCompressedData) compressedFactory.nextObject();

        } catch (Exception e) {
            Exceptions.dump(e);
            throw new MinigmaException("Minigma-unLock() 3: error reading encrypted data stream", e);
        }
    }

    private static byte[] decompress (PGPCompressedData clearCompressedData) throws MinigmaException{
        PGPLiteralData literalData=null;
        try {
            InputStream inputStream = clearCompressedData.getDataStream();
            JcaPGPObjectFactory decompressedFactory = new JcaPGPObjectFactory(inputStream);
            boolean moreObjects=true;
            while ((literalData==null)&&(moreObjects)) {
                Object decompressedObject = decompressedFactory.nextObject();
                if (decompressedObject==null){moreObjects=false;}
                if (decompressedObject instanceof PGPLiteralData) {
                    literalData = (PGPLiteralData) decompressedObject;
                }
            }
            return MinigmaUtils.readStream(literalData.getDataStream());
        }catch(Exception e){
            Exceptions.dump(e);
            throw new MinigmaException( "Minigma-unLock() 4: error getting decompressed object", e );
        }
    }

    /**
     * Returns a byte array of encrypted data. The resultant binary data must be base64 encoded
     * for transport by text systems such as xml.
     * @param compressedData
     * @param lock
     * @return
     * @throws MinigmaException
     */
    @SuppressWarnings("resource")
    public static byte[] encrypt (byte[] compressedData, Lock lock) throws MinigmaException{
        Minigma.initialiseProvider();
        PGPEncryptedDataGenerator encryptedDataGenerator=configureGenerator(Algorithms.SYMMETRIC_ALGORITHM,lock);
        ByteArrayOutputStream encryptedByteStream = new ByteArrayOutputStream();
        OutputStream outputStream;

        try {
            outputStream = encryptedDataGenerator.open(encryptedByteStream, compressedData.length);
        }catch(PGPException pgpe) {
            Exceptions.dump(pgpe);
            throw new MinigmaException("Error generating cypher: have you installed the unlimited strength policy files?", pgpe);
        }catch(Exception e){
            Exceptions.dump(e);
            throw new MinigmaException("Error generating cypher: refer to stack trace for details", e);

        }try{
            outputStream.write(compressedData);
            outputStream.flush();
            outputStream.close();
            byte[] encryptedBytes = encryptedByteStream.toByteArray();
            encryptedDataGenerator.close();
            return encryptedBytes;
        }catch(Exception e){
            Exceptions.dump(e);
            throw new MinigmaException("Cryptoengine-encrypt: ", e);
        }
    }

    private  static PGPEncryptedDataGenerator configureGenerator(int algorithm, Lock lock) throws MinigmaException {
        PGPEncryptedDataGenerator encryptedDataGenerator;

        try{
            JcePGPDataEncryptorBuilder pgpDataEncryptorBuilder = new JcePGPDataEncryptorBuilder(algorithm);
            pgpDataEncryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            encryptedDataGenerator = new PGPEncryptedDataGenerator(pgpDataEncryptorBuilder);
            Iterator<PGPPublicKeyRing> it = lock.getPGPPublicKeyRingIterator();
            if (!it.hasNext()){
                throw new MinigmaException("Empty Lock: "+lock.toString());
            }
            while (it.hasNext()){
                PGPPublicKeyRing keyRing = it.next();
                Iterator<PGPPublicKey> publicKeyIterator = keyRing.getPublicKeys();
                while(publicKeyIterator.hasNext()){
                    PGPPublicKey pgpPublicKey = publicKeyIterator.next();
                    if(pgpPublicKey.isEncryptionKey()){
                        PGPKeyEncryptionMethodGenerator methodGenerator = new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey);
                        encryptedDataGenerator.addMethod(methodGenerator);
                        System.out.println("added encryption method for keyID "+ Kidney.toString(pgpPublicKey.getKeyID()));
                    }
                }
            }
            return encryptedDataGenerator;
        }catch(Exception e){
              throw new MinigmaException("Minigma-encrypt: error configuring generator",e);
        }
    }
}
