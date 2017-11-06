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
package uk.co.platosys.dinigma;

import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import uk.co.platosys.dinigma.engines.CryptoEngine;
import uk.co.platosys.dinigma.engines.SignatureEngine;
import uk.co.platosys.dinigma.exceptions.MinigmaException;
import uk.co.platosys.dinigma.exceptions.SignatureException;
import uk.co.platosys.dinigma.exceptions.UnsupportedAlgorithmException;
import uk.co.platosys.dinigma.utils.Kidney;
import uk.co.platosys.dinigma.utils.MinigmaUtils;


/**
 *  In Minigma, a Lock is the object used to lock something; once locked, it can
 * only be opened with a matching Key.
 * 
 * Minigma Keys and Locks correspond to private keys and
 * public keys in other asymmetric crypto systems.
 *
 * Minigma is a fairly lightweight wrapper to OpenPGP, so an Minigma Lock can be instantiated
 * from OpenPGP public key material. Locks are saved as a file in PGP Ascii-armored format,
 * which is a Base64-encoding with headers and footers.
 * 
 * Locks can be concatenated, so one can be instantiated for a group of people. If 
 * this concatenated Lock is used to lock something, the locked object can be unlocked
 * by any of the corresponding Keys.
 *
 * @author edward
 * 
 * 
 */
public class Lock {

		private PGPPublicKeyRingCollection publicKeys;
      private static String TAG = "Lock";
        private KeyFingerPrintCalculator calculator;
        
        public static final String MULTIPLE_LOCK="multiple lock";
        private long lockID;
      
        /**
         * This is the standard way to instantiate a Lock object. LockSmith will have 
         * created the lock and written it to a file. 
         * @param file
         */
        public Lock(File file) throws MinigmaException {
        	InputStream keyIn;
        	try{
        		keyIn = new ArmoredInputStream(new FileInputStream(file));
        	}catch(IOException iox){
        		throw new MinigmaException("problem opening lock file", iox);
        	}try{
        		calculator = new JcaKeyFingerprintCalculator();
        		this.publicKeys = new PGPPublicKeyRingCollection(keyIn, calculator);
                PGPPublicKeyRing keyRing = (PGPPublicKeyRing) publicKeys.getKeyRings().next();
                PGPPublicKey pubkey = keyRing.getPublicKey();
                long keyID = pubkey.getKeyID();
                lockID=keyID;
        	}catch(PGPException pgpx){
        		throw new MinigmaException("problem instantiating lock key ring", pgpx);
        	}catch(IOException iox){
        		throw new MinigmaException("problem reading lock file", iox);
        	}
        	
        }
        /**
         * Creates a Lock object from base64-encoded OpenPGP public key material
         * @param encoded the base64-encoded string
         */
        public Lock(String encoded){
        	init(encoded);
        }
        private void init(String encoded){
         try{
            byte[] bytes = MinigmaUtils.decode(encoded);
            ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
            KeyFingerPrintCalculator kfpc = new JcaKeyFingerprintCalculator();
            this.publicKeys = new PGPPublicKeyRingCollection(bis, kfpc);
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) publicKeys.getKeyRings().next();
            PGPPublicKey pubkey = keyRing.getPublicKey();
            long keyID = pubkey.getKeyID();
            lockID=keyID;
         }catch(Exception x){
             Log.d(TAG,"problem creating Lock from encoded string", x);
         }
        }
        
        
        public Lock(PGPPublicKeyRingCollection publicKeyRingCollection){
            this.publicKeys=publicKeyRingCollection;
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) publicKeys.getKeyRings().next();
            PGPPublicKey pubkey = keyRing.getPublicKey();
            long keyID = pubkey.getKeyID();
            lockID=keyID;
         }

     /**
        Encrypts a String with this Lock
         */
        public  String lock(String string) throws MinigmaException{
          byte[] literalData=MinigmaUtils.toByteArray(string);
          MinigmaUtils.printBytes(literalData);
          byte[] compressedData = MinigmaUtils.compress(literalData);
          MinigmaUtils.printBytes(compressedData);
          byte[] encryptedData=CryptoEngine.encrypt(compressedData, this);
          return MinigmaUtils.encode(encryptedData);
        }
          
 /**
   * @return true if it verifies against this Lock, false otherwise.
   * @throws MinigmaException
   * @throws UnsupportedAlgorithmException
   * @throws SignatureException if the signature does not verify correctly.
   */
  public  boolean verify(String signedMaterial, String signature)throws MinigmaException, UnsupportedAlgorithmException, SignatureException {
	  	List<Long> signorIDS;
        signorIDS = SignatureEngine.verify(signedMaterial, signature, this);
        if(signorIDS.contains(lockID)){
           return true;
        }else{
        	return false;
        }
  }


        /**
         * Adds a Lock to this lock, concatenating the two. Material locked with the
         * resulting concatenated Lock can be unlocked with *any* of the corresponding
         * Keys.
         * @param lock the Lock to be added to this Lock
         * @return a Lock which can be unlocked by the keys corresponding to either Lock.
         */
        public Lock addLock(Lock lock){
            try{
            Iterator<PGPPublicKeyRing> keys = lock.getKeys();
            while(keys.hasNext()){
		PGPPublicKeyRing key = keys.next();
                long keyID = key.getPublicKey().getKeyID();
		if (!(publicKeys.contains(keyID))){
			PGPPublicKeyRingCollection.addPublicKeyRing(publicKeys, key);
		}
		
            }
             }catch(Exception x){
                Log.d(TAG,"problem adding lock to lock", x);
            }
            return this;

        }
/**
 * Removes a lock. Use this method with caution! it removes all references to any public key referred to by the Lock argument.
 * This could include a key that has been added by way of another Lock. So remove carefully.
 * @param lock the Lock to be removed;
 * @return this Lock, but with the other Lock removed
 */
public Lock removeLock(Lock lock){
	Iterator<PGPPublicKeyRing> keys = lock.getKeys();
	try{
        while(keys.hasNext()){
		PGPPublicKeyRing key = keys.next();
 long keyID = key.getPublicKey().getKeyID();
		if (!(publicKeys.contains(keyID))){
			PGPPublicKeyRingCollection.removePublicKeyRing(publicKeys, key);
		}
	}
        }catch(Exception x){
            Log.d(TAG,"problem removing lock",x );
        }
	return this;
}

/**
 *
 * @return
 */
public Iterator<PGPPublicKeyRing> getKeys(){
	//Log.d(TAG,4, "Lock.getKeys: publicKeys is: " +publicKeys.toString());
	
	return publicKeys.getKeyRings();
}

/**
 *
 * @return
 */
protected PGPPublicKeyRingCollection getKeyRings(){
    try{
        return publicKeys;
    }catch(Exception ex){
        Log.d(TAG, "problem with PGPPublicKeyRingCollection method in Lock class", ex);
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
        return publicKeys.getPublicKeyRing(keyID);
    }catch(Exception e){
        Log.d(TAG,"problem getting key ring", e);
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
 *Certifies a PGP public key within this Lock.
 *
 * @param keyID the keyID of the public key to be certified
 * @param key the key of the person doing the certifying
 * @param passphrase the corresponding passphrase
 * @throws MinigmaException
 */
public void certify(long keyID, Key key, char [] passphrase) throws MinigmaException {
         try{
            if(publicKeys.contains(keyID)){
                try{
                    PGPPublicKeyRing pkr = publicKeys.getPublicKeyRing(keyID);
                    PGPPublicKey publicKey = pkr.getPublicKey(keyID);
                    PGPSignature signature = SignatureEngine.getKeyCertification(key, passphrase, publicKey);
                    PGPPublicKey.addCertification(publicKey, signature);
                }catch(Exception x){
                    Log.d(TAG,"problem certifying key,", x);
                }
            }else{
                throw new MinigmaException ("key "+Kidney.toString(keyID)+ " not in this lock");
            }
         }catch(Exception x){
            throw new MinigmaException("certification issues", x);
            
         }



}


/**
 *
 * @return
 */
public long getLockID(){
    return lockID;
}
}