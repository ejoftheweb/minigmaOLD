package uk.co.platosys.minigma;
/*
Copyright (C) 2017 Edward Barrow and Platosys

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy,
modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software
 is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL EDWARD BARROW OR
PLATOSYS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 */





import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.exceptions.NoDecryptionKeyException;
import uk.co.platosys.minigma.utils.Kidney;
import uk.co.platosys.minigma.utils.MinigmaUtils;


/**
 * In Minigma, a Key is the object used to unlock something that has been locked
 * with a corresponding Lock. Minigma Keys and Locks correspond to private keys and
 * public keys respectively in other asymmetric crypto systems.
 *
 * Minigma is a fairly lightweight wrapper to OpenPGP, so a Minigma Key can be instantiated
 * from OpenPGP private key material.
 *
 * HOWEVER: OpenPGP private key material does not include the UserID. The KeyID or fingerprint can be deduced from the
 * key material, but not the relevant userID (which is, generally, an email address). Therefore, you need to look up the
 * associated userID from a keyring, or in Minigma, a Lockstore, using lockstore.getUserId(long keyid) every time you use the
 * key for signing.
 * Minigma therefore provides a set of overloaded constructors which take a LockStore argument which should be used for creating
 * signing keys.
 *
 * A Key always needs a passphrase.
 * @author edward
 *
 *
 *
 */
public class Key {

    private PGPSecretKey signingKey;
    private PGPSecretKey masterKey;
    private PGPSecretKeyRingCollection secretKeyRingCollection;
    private byte[] keyID;
    private String userID="";


    /** @param secretKeyRingCollection
     */
    protected Key(PGPSecretKeyRingCollection secretKeyRingCollection) throws Exception{
        this.secretKeyRingCollection=secretKeyRingCollection;
        init(null);
    }


    /** @param keyFile  a java.io.File object pointing to  a text file of OpenPGP key material
     */

    public Key(File keyFile)throws MinigmaException {
        try{
            FileInputStream fileStream=new FileInputStream(keyFile);
            InputStream instream=new ArmoredInputStream(fileStream);
            instream=PGPUtil.getDecoderStream(instream);
            KeyFingerPrintCalculator kfpc = new BcKeyFingerprintCalculator();
            this.secretKeyRingCollection = new PGPSecretKeyRingCollection(instream, kfpc);
            init(null);
            instream.close();
            fileStream.close();
        }catch(Exception x){
            throw new MinigmaException("problem loading Key from file", x);
        }
    }
    public Key(InputStream inputStream)throws MinigmaException {
        try{
            InputStream instream=new ArmoredInputStream(inputStream);
            instream=PGPUtil.getDecoderStream(instream);
            KeyFingerPrintCalculator kfpc = new BcKeyFingerprintCalculator();
            this.secretKeyRingCollection = new PGPSecretKeyRingCollection(instream, kfpc);
            init(null);
            instream.close();
            inputStream.close();
        }catch(Exception x){
           throw new MinigmaException("problem loading Key from input stream", x);
        }
    }
    /** @param keyFile  a java.io.File object pointing to  a text file of OpenPGP key material
     */

    public Key(File keyFile, LockStore lockStore)throws MinigmaException {
        try{
            FileInputStream fileStream=new FileInputStream(keyFile);
            InputStream instream=new ArmoredInputStream(fileStream);
            instream=PGPUtil.getDecoderStream(instream);
            KeyFingerPrintCalculator kfpc = new BcKeyFingerprintCalculator();
            this.secretKeyRingCollection = new PGPSecretKeyRingCollection(instream, kfpc);
            init(lockStore);
            instream.close();
            fileStream.close();
        }catch(Exception x){
            throw new MinigmaException("problem loading Key from file", x);
        }
    }
    public Key(InputStream inputStream, LockStore lockStore)throws MinigmaException {
        try{
            InputStream instream=new ArmoredInputStream(inputStream);
            instream=PGPUtil.getDecoderStream(instream);
            KeyFingerPrintCalculator kfpc = new BcKeyFingerprintCalculator();
            this.secretKeyRingCollection = new PGPSecretKeyRingCollection(instream, kfpc);
            init(lockStore);
            instream.close();
            inputStream.close();
        }catch(Exception x){
            throw new MinigmaException("problem loading Key from input stream", x);
        }
    }
    private void init(LockStore lockStore) throws Exception{
        try{
            signingKey = null;
            masterKey=null;
            //decryptionKey = null;
            Iterator<PGPSecretKeyRing> ringIterator = secretKeyRingCollection.getKeyRings();
            while ((signingKey == null) && ringIterator.hasNext()){
                PGPSecretKeyRing  pgpSecretKeyRing = ringIterator.next();
                Iterator<PGPSecretKey> keyIterator = pgpSecretKeyRing.getSecretKeys();
                while ((signingKey == null) && keyIterator.hasNext()){
                    PGPSecretKey key = keyIterator.next();
                    if (key.isSigningKey()){
                        signingKey = key;
                        keyID = signingKey.getPublicKey().getFingerprint();
                        if(lockStore!=null){
                            this.userID=lockStore.getUserID(keyID);
                        }
                    }else if (key.isMasterKey()){
                        masterKey=key;
                   }
                }
            }
            if (signingKey == null) {
                throw new IllegalArgumentException("Can't find signing key in key ring.");
            }
        }catch(Exception e){
            throw e;
        }
    }
    /** @return the keyID for this key;*/
    public byte[] getKeyID(){return keyID;}
    public long getLongKeyID(){
        Fingerprint fingerprint = new Fingerprint(keyID);
        return fingerprint.getKeyID();
    }
    /** @return the primary userID associated with this key;
     * or the empty string*/
    public String getUserID() {return userID;}

    /**
     *
     * @return
     */
   protected PGPSecretKey getSigningKey(){
        return signingKey;
    }
   protected PGPSecretKey getMasterKey(){return masterKey;}

    /**
     *Returns an BouncyCastle PGPSecretKey decryption key, to be used to
     * decrypt/unlock something.
     * @param keyID
     * @return
     */
    protected PGPSecretKey getDecryptionKey(long keyID) throws MinigmaException, NoDecryptionKeyException{
        try{
            if (secretKeyRingCollection.contains(keyID)) {
                return secretKeyRingCollection.getSecretKey(keyID);
            }else{
                throw new NoDecryptionKeyException("Key does not decrypt key with id:"+ Kidney.toString(keyID));
            }
        }catch(NoDecryptionKeyException ndke) {
            throw ndke;
        }catch(Exception e){
            throw new MinigmaException("Key-getDecryptionKey exception", e);
        }
    }

    /**
     * @param toBeSigned the String to be signed
     * @param passphrase
     * @return a Base64-encoded signature String.
     * @throws MinigmaException
     */
    public Signature sign(String toBeSigned, char[] passphrase, LockStore lockStore) throws MinigmaException{
        String digest= Digester.digest(toBeSigned);
        return SignatureEngine.sign(digest, this, passphrase, lockStore);
    }
    /**
     * @param toBeSigned the String to be signed
     * @param passphrase
     * @return a Base64-encoded signature String.
     * @throws MinigmaException
     */
    public Signature sign(String toBeSigned, List<Notation> notations, char[] passphrase, LockStore lockStore) throws MinigmaException{
        String digest= Digester.digest(toBeSigned);
        return SignatureEngine.sign(digest, this, notations, passphrase, lockStore);
    }
    /**
     * This takes ciphertext and returns  the cleartext
     *
     * @param ciphertext to be unlocked
     * @param passphrase This key's passphrase
     * @return a cleartext String
     * @throws Exception
     */
    public String unlock(String ciphertext, char[] passphrase) throws Exception {
        return unlockAsString(MinigmaUtils.decode(ciphertext),passphrase);
    }
    public String unlockAsString(byte[] bytes, char[] passphrase) throws Exception {
        return new String( unlockAsBytes(bytes,passphrase), "UTF-8");
    }
    public byte[] unlockAsBytes
            (byte[] bytes, char[] passphrase) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
         return CryptoEngine.decrypt(bais, this, passphrase);

    }

}
