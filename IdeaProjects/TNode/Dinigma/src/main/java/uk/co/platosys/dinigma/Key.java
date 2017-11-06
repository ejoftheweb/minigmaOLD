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



import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import uk.co.platosys.dinigma.engines.CryptoEngine;
import uk.co.platosys.dinigma.engines.Digester;
import uk.co.platosys.dinigma.engines.SignatureEngine;
import uk.co.platosys.dinigma.exceptions.MinigmaException;
import uk.co.platosys.dinigma.utils.Kidney;
import uk.co.platosys.dinigma.utils.MinigmaUtils;


/**
 *  In Minigma, a Key is the object used to unlock something that has been locked
 * with a corresponding Lock. Minigma Keys and Locks correspond to private keys and
 * public keys in other asymmetric crypto systems.
 *
 * Minigma is a fairly lightweight wrapper to OpenPGP, so an Minigma Key can be instantiated
 * from OpenPGP private key material.
 *
 * A Key always needs a passphrase.
 * @author edward
 *
 *
 *
 */
public class Key {

private PGPSecretKey signingKey;
private static String TAG ="Key";
private PGPSecretKeyRingCollection skrc;
private long keyID;


/** @param skrc
 */
protected Key(PGPSecretKeyRingCollection skrc){
    this.skrc=skrc;
    init();
}


/** @param keyFile  a java.io.File object pointing to  a text file of OpenPGP key material
*/
@SuppressWarnings("resource")
public Key(File keyFile)throws MinigmaException {
 	try{
		FileInputStream fileStream=new FileInputStream(keyFile);
		InputStream instream=new ArmoredInputStream(fileStream);
	   instream=PGPUtil.getDecoderStream(instream);
	   KeyFingerPrintCalculator kfpc = new BcKeyFingerprintCalculator();
	  skrc = new PGPSecretKeyRingCollection(instream, kfpc);
          init();
          instream.close();
          fileStream.close();
        }catch(Exception x){
            Log.d(TAG, "problem loading Key from file", x);
            throw new MinigmaException("problem loading Key from file", x);
        }
}
    public Key(InputStream inputStream)throws MinigmaException {
      try{
            InputStream instream=new ArmoredInputStream(inputStream);
            instream=PGPUtil.getDecoderStream(instream);
            KeyFingerPrintCalculator kfpc = new BcKeyFingerprintCalculator();
            skrc = new PGPSecretKeyRingCollection(instream, kfpc);
            init();
            instream.close();
            inputStream.close();
        }catch(Exception x){
            Log.d(TAG, "problem loading Key from input stream", x);
            throw new MinigmaException("problem loading Key from input stream", x);
        }
    }
 private void init(){
   try{
      signingKey = null;
      //decryptionKey = null;
      Iterator<PGPSecretKeyRing> ringIterator = skrc.getKeyRings();
      while ((signingKey == null) && ringIterator.hasNext()){
          PGPSecretKeyRing  pgpSecretKeyRing = ringIterator.next();    
          Iterator<PGPSecretKey> keyIterator = pgpSecretKeyRing.getSecretKeys();
          while ((signingKey == null) && keyIterator.hasNext()){
              PGPSecretKey key = keyIterator.next();              
              if (key.isSigningKey()){
                  signingKey = key;
                  keyID = signingKey.getKeyID();

             }
          }
      }
      if (signingKey == null) {
          throw new IllegalArgumentException("Can't find signing key in key ring.");
      }
    }catch(Exception e){
		Log.d(TAG,"K-init problemo", e);
	}
}
 /**
  *
  * @return the keyID for this key;
  */
 public long getKeyID(){
     return keyID;
 }
 /**
  *
  * @return
  */
 public PGPSecretKey getSigningKey(){
	return signingKey;
}

/**
 *
 * @param keyID
 * @return
 */
public PGPSecretKey getDecryptionKey(long keyID){
    try{
	return skrc.getSecretKey(keyID);
    }catch(Exception e){
        Log.d(TAG,"Key: couldn't find decryption key for "+Kidney.toString(keyID));
        return null;
    }
}
 
/**
* @param toBeSigned the String to be signed
 * @param passphrase
 * @return a Base64-encoded signature String.
 * @throws MinigmaException
 */
public String sign(String toBeSigned, char[] passphrase) throws MinigmaException{
    String digest= Digester.digest(toBeSigned);
	return SignatureEngine.sign(digest, this, passphrase);
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
	  byte[] bytes = MinigmaUtils.decode(ciphertext);
	  ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
	  String cleartext=CryptoEngine.decrypt(bais, this, passphrase);
	  return cleartext;
}

}