/*
 * Copyright Edward Barrow and Platosys.
 * This software is licensed under the Free Software Foundation's
General Public Licence, version 2 ("the GPL").
The full terms of the licence can be found online at http://www.fsf.org/

In brief, you are free to copy and to modify the code in any way you wish, but if you
publish the modified code you may only do so under the GPL, and (if asked) you must
 supply a copy of the source code alongside any compiled code.

Platosys software can also be licensed on negotiated terms if the GPL is inappropriate.
For further information about this, please contact software.licensing@platosys.co.uk
 */
package uk.co.platosys.minigma;



import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.exceptions.SignatureException;
import uk.co.platosys.minigma.exceptions.UnsupportedAlgorithmException;
import uk.co.platosys.minigma.utils.Kidney;
import uk.co.platosys.minigma.utils.MinigmaUtils;


/**
 *  In Minigma, a Lock is the object used to lock something; once locked, it can
 * only be opened with a matching Key.
 *
 * Minigma Keys and Locks correspond to private keys and
 * public keys in other asymmetric crypto systems.
 *
 * Minigma is a fairly lightweight wrapper to OpenPGP, so a Minigma Lock can be instantiated
 * from OpenPGP public key material.
 *
 * Locks can be concatenated, so one can be instantiated for a group of people. If 
 * this concatenated Lock is used to lock something, the locked object can be unlocked
 * by ANY of the corresponding Keys. We have plans for, but have not yet implemented a Lock concatenation
 * in which ALL of the corresponding Keys are required.
 *
 * A Lock object is normally instantiated by obtaining it from a LockStore.
 *
 * Note that the lockID and the fingerprint are the SAME thing - the fingerprint is an
 * object wrapper for the byte array that is the lockID.
 *
 * @author edward
 *
 *
 */
public class Lock {

    private PGPPublicKeyRingCollection publicKeyRingCollection;
    private static String TAG = "Lock";
    private KeyFingerPrintCalculator calculator;
    //public static final String MULTIPLE_LOCK="multiple lock";
    private byte[] lockID;
    private Fingerprint fingerprint;
    private PGPPublicKey publicKey;
    private String userID;



    /**
     * Creates a Lock object from base64-encoded OpenPGP public key material
     * @param encoded the base64-encoded string containing the public key
     */
    public Lock(String encoded)throws MinigmaException{
        init(encoded);
    }
    private void init(String encoded) throws MinigmaException{
        try{
            byte[] bytes = MinigmaUtils.decode(encoded);
            ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
            KeyFingerPrintCalculator keyFingerPrintCalculator = new JcaKeyFingerprintCalculator();
            this.publicKeyRingCollection = new PGPPublicKeyRingCollection(bis, keyFingerPrintCalculator);
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) publicKeyRingCollection.getKeyRings().next();
            this.publicKey = keyRing.getPublicKey();
            this.lockID=publicKey.getFingerprint();
            this.fingerprint=new Fingerprint(lockID);

        }catch(Exception x){
           throw new MinigmaException("error initialising minigma-lock from string", x);
        }
    }
/**
 * Instantiates a Lock from an AsciiArmored file
 *
 */
public Lock(File file) throws MinigmaException{
    try {
        ArmoredInputStream armoredInputStream = new ArmoredInputStream(new FileInputStream(file));
        KeyFingerPrintCalculator calculator = new JcaKeyFingerprintCalculator();
        PGPPublicKeyRingCollection keyRings=new PGPPublicKeyRingCollection(armoredInputStream, calculator);
        init(keyRings);
    }catch(IOException iox){
        throw new MinigmaException("Lock(file) error opening lock file", iox);
    }catch(PGPException pex){
        throw new MinigmaException("Lock(file) error instantiating KeyRingCollection", pex);
    }
}
    /**
     * This constructor takes a BouncyCastle PGPPublicKeyRingCollection and
     * instantiates a Lock from the first public key ring in the collection.
     * @param publicKeyRingCollection
     */

    protected Lock(PGPPublicKeyRingCollection publicKeyRingCollection) {
        init(publicKeyRingCollection);
    }
    private void init(PGPPublicKeyRingCollection publicKeyRingCollection){
        try {
            this.publicKeyRingCollection = publicKeyRingCollection;
          PGPPublicKeyRing keyRing = (PGPPublicKeyRing) publicKeyRingCollection.getKeyRings().next();
            PGPPublicKey pubkey = keyRing.getPublicKey();
            this.publicKey=pubkey;
            Iterator<String> userids = pubkey.getUserIDs();

            this.lockID=publicKey.getFingerprint();
            this.fingerprint=new Fingerprint(lockID);
            //System.out.println(Kidney.toString(lockID));
           //System.out.println(Kidney.toString(fingerprint));
        }catch(Exception x){
            Exceptions.dump(x);

        }
    }
    /**
     *
     */
    protected Lock(PGPPublicKeyRing pgpPublicKeyRing){
        try {
            Collection<PGPPublicKeyRing> keyList= new ArrayList<PGPPublicKeyRing>();
            keyList.add(pgpPublicKeyRing);
            this.publicKeyRingCollection = new PGPPublicKeyRingCollection(keyList);
        }catch (Exception x){
            Exceptions.dump(x);
        }
        PGPPublicKey pubkey = pgpPublicKeyRing.getPublicKey();
        this.publicKey=pubkey;
        this.lockID=publicKey.getFingerprint();
        this.fingerprint=new Fingerprint(lockID);
    }

    /**
     Encrypts a String with this Lock
     */
    public  byte[] lock(String string) throws MinigmaException{
         return lock(MinigmaUtils.toByteArray(string));

    }

    /**
     Encrypts a byte array with this Lock
     */
    public  byte[] lock(byte[] literalData) throws MinigmaException{
        //MinigmaUtils.printBytes(literalData);
        byte[] compressedData = MinigmaUtils.compress(literalData);
        //MinigmaUtils.printBytes(compressedData);
        byte[] encryptedData=CryptoEngine.encrypt(compressedData, this);
        return encryptedData;
    }
    public String lockAsString(String string) throws MinigmaException{
        return MinigmaUtils.encode(lock(string));
    }

    /**
     * @return true if it verifies against this Lock, false otherwise.
     * @throws MinigmaException
     * @throws UnsupportedAlgorithmException
     * @throws SignatureException if the signature does not verify correctly.
     */
    public  boolean verify(String signedMaterial, Signature signature)throws MinigmaException, UnsupportedAlgorithmException, SignatureException {
        List<List<Fingerprint>> results= SignatureEngine.verify(signedMaterial, signature, this);
        List<Fingerprint> signorIDS=results.get(0);
        if(signorIDS.contains(fingerprint)){

            return true;
        }else{
            return false;
        }
    }


    /**
     * Adds a Lock to this lock, concatenating the two. Material locked with the
     * resulting concatenated Lock can be unlocked with *any* of the corresponding
     * Keys, unless inclusive is true in which case *all* the Keys are needed. However,
     * this feature is not yet implemented and passing inclusive as true will cause an exception to be thrown.
     * @param lock the Lock to be added to this Lock
     * @param inclusive must be false in this implementation.
     * @return a Lock which can be unlocked by the keys corresponding to either Lock.
     */
    public Lock addLock(Lock lock, boolean inclusive) throws MinigmaException{
        if(inclusive){throw new MinigmaException("inclusive Lock concatenation not yet implemented");}
        long newLockID=0;
        try{
            Iterator<PGPPublicKeyRing> pgpPublicKeyRingIterator = lock.getPGPPublicKeyRingIterator();
            while(pgpPublicKeyRingIterator.hasNext()){
                PGPPublicKeyRing pgpPublicKeyRing = pgpPublicKeyRingIterator.next();
                newLockID = pgpPublicKeyRing.getPublicKey().getKeyID();
                if (!(publicKeyRingCollection.contains(newLockID))){
                    publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRingCollection, pgpPublicKeyRing);
                    //System.out.println("Lock: added lock with ID:"+Kidney.toString(newLockID)+" to lock "+Kidney.toString(lockID));
                }
            }
            //System.out.println("concatenation completed, this lock now has "+publicKeys.size()+" locks");
        }catch(Exception x){
            throw new MinigmaException("Error concatenating Lock", x);
        }

        return this;
   }
    /**
     * Removes a lock. Use this method with caution! it removes all references to any public key referred to by the Lock argument.
     * This could include a key that has been added by way of another Lock. So remove carefully.
     * @param lock the Lock to be removed;
     * @return this Lock, but with the other Lock removed
     */
    public Lock removeLock(Lock lock)throws MinigmaException{
        Iterator<PGPPublicKeyRing> pgpPublicKeyRingIterator = lock.getPGPPublicKeyRingIterator();
        try{
            while(pgpPublicKeyRingIterator.hasNext()){
                PGPPublicKeyRing pgpPublicKeyRing = pgpPublicKeyRingIterator.next();
                long keyID = pgpPublicKeyRing.getPublicKey().getKeyID();
                if (publicKeyRingCollection.contains(keyID)){
                    publicKeyRingCollection=PGPPublicKeyRingCollection.removePublicKeyRing(publicKeyRingCollection, pgpPublicKeyRing);
                }
            }
        }catch(Exception x){
            throw new MinigmaException("Error de-concatenating Lock", x);
        }
        return this;
    }

    /**Revokes a particular public key in a Lock, generating a key revocation Certificate
     *
     * @param keyID the 64-bit ID of the public key to be revoked
     * @param key its corresponding key
     * @param passphrase and the passphrase
     * @return
     */
    public Certificate revokeLock (long keyID, Key key, char[] passphrase){
        try {
            PGPPublicKeyRing pgpPublicKeyRing = publicKeyRingCollection.getPublicKeyRing(keyID);
            PGPPublicKey pgpPublicKey = pgpPublicKeyRing.getPublicKey(keyID);
            return revokeLock(pgpPublicKey, key, passphrase);
        }catch(PGPException pgpx){
            Exceptions.dump(pgpx);
            return null;
        }

    }
    /**Revokes a particular public key in a Lock, generating a key revocation Certificate
     *
     * @param keyID the 160-bit fingerprint of the public key to be revoked
     * @param key
     * @param passphrase
     * @return
     */
    public Certificate revokeLock (byte[] keyID, Key key, char[] passphrase){
        try {
            PGPPublicKeyRing pgpPublicKeyRing = publicKeyRingCollection.getPublicKeyRing(keyID);
            PGPPublicKey pgpPublicKey = pgpPublicKeyRing.getPublicKey(keyID);
            return revokeLock(pgpPublicKey, key, passphrase);
        }catch(PGPException pgpx){
            Exceptions.dump(pgpx);
            return null;
        }
    }
    private Certificate revokeLock (PGPPublicKey pgpPublicKey, Key key, char[] passphrase){
        try{
            PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpPublicKey.getAlgorithm(), HashAlgorithmTags.SHA512));
            PBESecretKeyDecryptor pbeSecretKeyDecryptor = new JcePBESecretKeyDecryptorBuilder().build(passphrase);
            PGPPrivateKey pgpPrivateKey = key.getSigningKey().extractPrivateKey(pbeSecretKeyDecryptor);
            pgpSignatureGenerator.init(0x20, pgpPrivateKey);
            PGPSignature revocationSignature = pgpSignatureGenerator.generateCertification(pgpPublicKey);
            pgpPublicKey = PGPPublicKey.addCertification(pgpPublicKey,revocationSignature);
            return new Certificate(revocationSignature, key.getUserID());
        }catch(PGPException pgpex){
            Exceptions.dump(pgpex);
            return null;
        }
    }
    public Certificate addDesignatedRevoker (byte[] lockid, Key key, char[] passphrase){
        try {
            PGPSignatureSubpacketGenerator pgpSignatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
            pgpSignatureSubpacketGenerator.setRevocationKey(true, PublicKeyAlgorithmTags.RSA_SIGN, lockid);
            PGPSignatureSubpacketVector pgpSignatureSubpacketVector = pgpSignatureSubpacketGenerator.generate();
            PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_SIGN, HashAlgorithmTags.SHA512));
            PBESecretKeyDecryptor pbeSecretKeyDecryptor = new JcePBESecretKeyDecryptorBuilder().build(passphrase);
            PGPPrivateKey pgpPrivateKey = key.getMasterKey().extractPrivateKey(pbeSecretKeyDecryptor);
            pgpSignatureGenerator.init(PGPSignature.DIRECT_KEY,pgpPrivateKey);
            pgpSignatureGenerator.setHashedSubpackets(pgpSignatureSubpacketVector);
            PGPSignature revokerSignature = pgpSignatureGenerator.generate();
            publicKey = PGPPublicKey.addCertification(publicKey,revokerSignature);
            return new Certificate(revokerSignature, userID);

        }catch(Exception x){
            Exceptions.dump(x);
            return null;
        }


    }

    /**
     *
     * @return
     */
    public Iterator<PGPPublicKeyRing> getPGPPublicKeyRingIterator(){

        return publicKeyRingCollection.getKeyRings();
    }

    /**
     *
     * @return
     */
    protected PGPPublicKeyRingCollection getKeyRings(){
        try{
            return publicKeyRingCollection;
        }catch(Exception ex){
            return null;
        }
    }

    /**
     *
     * @param keyID
     * @return
     */
    protected PGPPublicKeyRing getPublicKeyRing(long keyID){
        try{
            return publicKeyRingCollection.getPublicKeyRing(keyID);
        }catch(Exception e){
            return null;
        }
    }
    /**
     *
     * @param keyID
     * @return
     */
    public PGPPublicKey getPublicKey(long keyID){
        PGPPublicKeyRing pkr = getPublicKeyRing(keyID);
        return pkr.getPublicKey();
    }
/*
public void revoke(long keyID, Key key, char[] passphrase) throws MinigmaException {
    if(publicKeys.containsKey(keyID)){
        PGPPublicKeyRing pkr = publicKeys.get(keyID);
        PGPPublicKey publicKey = pkr.getPublicKey(keyID);
        PGPPublicKey.addCertification(publicKey, null)
    }else{
        throw new MinigmaException ("key "+Kidney.toString(keyID)+ " not in this lock");
    }
}
 */
    /**
     *Certifies a specific PGP public key within this Lock.
     *
     * @param keyID the keyID of the public key to be certified
     * @param key the key of the person doing the certifying
     * @param passphrase the corresponding passphrase
     * @throws MinigmaException
     */
    public Certificate certify(long keyID, Key key, char [] passphrase, LockStore lockStore) throws MinigmaException {
        try{
            if(publicKeyRingCollection.contains(keyID)){
                try{
                    PGPPublicKeyRing pgpPublicKeyRing = publicKeyRingCollection.getPublicKeyRing(keyID);
                    PGPPublicKey publicKey = pgpPublicKeyRing.getPublicKey(keyID);
                    boolean isCertified = false;
                    Iterator signatures = publicKey.getSignatures();
                    while(signatures.hasNext()){
                        PGPSignature signature = (PGPSignature) signatures.next();
                        if(signature.isCertification()){
                           isCertified=(signature.getKeyID()==key.getLongKeyID());
                           if(isCertified){return new Certificate(signature, lockStore.getUserID(key.getKeyID()));}
                        }
                    }
                    if(! isCertified) {
                        PGPSignature pgpSignature = SignatureEngine.getKeyCertification(key, passphrase, publicKey);
                        publicKeyRingCollection = PGPPublicKeyRingCollection.removePublicKeyRing(publicKeyRingCollection, pgpPublicKeyRing);
                        pgpPublicKeyRing = PGPPublicKeyRing.removePublicKey(pgpPublicKeyRing, publicKey);
                        publicKey = PGPPublicKey.addCertification(publicKey, pgpSignature);
                        pgpPublicKeyRing = PGPPublicKeyRing.insertPublicKey(pgpPublicKeyRing, publicKey);
                        publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRingCollection, pgpPublicKeyRing);
                        lockStore.addLock(this);
                        return new Certificate(pgpSignature, lockStore.getUserID(key.getKeyID()));
                    }
                }catch(Exception x){
                    throw new MinigmaException("Problem certifying key", x);
                }
            }else{
                throw new MinigmaException ("key "+Kidney.toString(keyID)+ " not in this lock");
            }
        }catch(Exception x){
            Exceptions.dump(x);
            throw new MinigmaException("certification issues", x);

        }
        return null;
    }
    public List<Certificate> getCertificates(LockStore lockStore){
        List<Certificate> certificates = new ArrayList<>();
        for (PGPPublicKeyRing pgpPublicKeyRing : publicKeyRingCollection){
            Iterator<PGPPublicKey> pgpPublicKeyIterator = pgpPublicKeyRing.getPublicKeys();
            while (pgpPublicKeyIterator.hasNext()){
                PGPPublicKey pgpPublicKey = pgpPublicKeyIterator.next();
                Iterator signatureIterator = pgpPublicKey.getSignatures();
                while (signatureIterator.hasNext()) {
                    try {
                        PGPSignature pgpSignature = (PGPSignature) signatureIterator.next();
                        if (pgpSignature.isCertification()) {
                            long keyID = pgpSignature.getKeyID();
                            String signerUserID = lockStore.getUserID(keyID);
                            Certificate certificate = new Certificate(pgpSignature, signerUserID);
                            certificates.add(certificate);
                        }

                    }catch (ClassCastException ccx){
                        Exceptions.dump(ccx);
                        //TODO handle
                    }
                }
            }
        }
        return certificates;
    }

    public boolean contains (long lockID) {
        try {
            return publicKeyRingCollection.contains(lockID);
        }catch (Exception x){
            Exceptions.dump(x);
            return false;
        }
    }
    public boolean contains (byte[] lockID) {
        try {
            return publicKeyRingCollection.contains(lockID);
        }catch (Exception x){
            Exceptions.dump(x);
            return false;
        }
    }


    /**
     *
     * @return
     */
    public byte[] getLockID(){
        return lockID;
    }
    public Fingerprint getFingerprint(){
        return fingerprint;
    }
    public byte[] getBytes(){
        try {
            return publicKeyRingCollection.getEncoded();
        }catch(IOException iox){
            Exceptions.dump(iox);
            return null;
        }
    }
    public String getUserID(){
        return userID;
    }
}