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
package uk.co.platosys.dinigma.engines;

import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPCompressedData;
import org.spongycastle.openpgp.PGPObjectFactory;
import org.spongycastle.openpgp.PGPPrivateKey;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPSecretKey;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.PGPSignatureGenerator;
import org.spongycastle.openpgp.PGPSignatureList;
import org.spongycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.spongycastle.openpgp.PGPSignatureSubpacketVector;
import org.spongycastle.openpgp.PGPUtil;
import org.spongycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.spongycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.spongycastle.openpgp.operator.PGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import uk.co.platosys.dinigma.Key;
import uk.co.platosys.dinigma.Lock;
import uk.co.platosys.dinigma.Minigma;
import uk.co.platosys.dinigma.exceptions.MinigmaException;
import uk.co.platosys.dinigma.utils.Kidney;
import uk.co.platosys.dinigma.utils.MinigmaUtils;


/**
 *
 * @author edward
 */
public class SignatureEngine {
    private static String TAG ="SignatureEngine";


  
  public static String sign(String string, Key key, char [] passphrase) throws MinigmaException{
      byte[] bytes = MinigmaUtils.toByteArray(string);
      return sign(bytes, key, passphrase);
  }
  static String sign(byte [] bytes, Key key, char[] passphrase) throws MinigmaException{
     try{
    	 PBESecretKeyDecryptor keyDecryptor =  new JcePBESecretKeyDecryptorBuilder()
         .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passphrase);
       PGPPrivateKey privateKey = key.getSigningKey().extractPrivateKey(keyDecryptor);
       PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(key.getSigningKey().getPublicKey().getAlgorithm(), Minigma.HASH_ALGORITHM);
       PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
       signatureGenerator.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey);
       PGPSignature signature = signatureGenerator.generate();
        signature.update(bytes, 0, 0);
       ByteArrayOutputStream bos = new ByteArrayOutputStream();
       signature.encode(bos);
       byte [] sigBytes = bos.toByteArray();
       return MinigmaUtils.encode(sigBytes);
      }catch(Exception e){
        Log.d(TAG,"error making signature", e);
        throw new MinigmaException("error making signature", e);
    }
   }
  
  public static List<Long> verify(String string, String signatureValue, Lock lock){
	  return verify(MinigmaUtils.toByteArray(string), signatureValue, lock);
  }
  static List<Long> verify(byte [] bytes, String signatureValue, Lock lock){
      List<Long> signors = new ArrayList<Long>();

      try{
    	  KeyFingerPrintCalculator calculator = new JcaKeyFingerprintCalculator();
       byte [] sigVal = MinigmaUtils.decode(signatureValue);
       //Log.d(TAG,"sigVal  = "+Kidney.toString(sigVal));
       ByteArrayInputStream bis = new ByteArrayInputStream(sigVal);
       InputStream in = PGPUtil.getDecoderStream(bis);
       PGPObjectFactory    pgpFactory = new PGPObjectFactory(in, calculator );
       PGPSignatureList    signatureList = null;
       Object    o = pgpFactory.nextObject();
       if (o instanceof PGPCompressedData) {
            PGPCompressedData compressedData = (PGPCompressedData)o;
             pgpFactory = new PGPObjectFactory(compressedData.getDataStream(), calculator);
            signatureList = (PGPSignatureList)pgpFactory.nextObject();
        }else{
            signatureList = (PGPSignatureList)o;
        }
        //Log.d(TAG,5, "signatureList has "+signatureList.size()+" signatures");

       for(int i=0; i<signatureList.size(); i++){
         PGPSignature signature = signatureList.get(i);
         long keyID = signature.getKeyID();
          //Log.d(TAG,5, "verifying against key "+Kidney.toString(keyID));

         PGPPublicKey publicKey = lock.getPublicKey(keyID);
         PGPContentVerifierBuilderProvider pgpContentVerifierBuilder = new JcaPGPContentVerifierBuilderProvider();//.get(keyAlgorithm, Minigma.HASH_ALGORITHM);
         signature.init(pgpContentVerifierBuilder, publicKey);
         signature.update(bytes, 0,0);
         if(signature.verify()){
             Log.d(TAG,  "signature verified against key "+Kidney.toString(keyID));
             signors.add(keyID);
         }else{
             Log.d(TAG, "signature NOT verified against key "+Kidney.toString(keyID));

         }
       }
      }catch(Exception x){

      }
      return signors;
  }
 
 public static PGPSignature getKeyCertification(Key key, char[] passphrase, PGPPublicKey keyToBeSigned){
        
        try{
            PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(key.getSigningKey().getPublicKey().getAlgorithm(), Minigma.HASH_ALGORITHM);
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
            PGPSignatureSubpacketGenerator subPacketGenerator = new PGPSignatureSubpacketGenerator();
            subPacketGenerator.setRevocable(true,true);
            subPacketGenerator.setSignatureCreationTime(true, new Date());
            PGPSignatureSubpacketVector packetVector = subPacketGenerator.generate();
            signatureGenerator.setHashedSubpackets(packetVector);
            PGPSignature signature = signatureGenerator.generateCertification(keyToBeSigned);
            return signature;
        }catch(Exception x){
            Log.d(TAG,"getKeyCertification error",x );
            return null;
        }
 }
        
  static PGPSignature getKeyRevocation(Key key, char [] passphrase, PGPPublicKey keyToBeRevoked){

        try{
            PGPSecretKey secretKey = key.getSigningKey();
            PBESecretKeyDecryptor keyDecryptor =  new JcePBESecretKeyDecryptorBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passphrase);
            PGPPrivateKey privateKey = key.getSigningKey().extractPrivateKey(keyDecryptor);
            
            PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), Minigma.HASH_ALGORITHM);
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
           signatureGenerator.init(PGPSignature.DIRECT_KEY,privateKey);
            PGPSignatureSubpacketGenerator subPacketGenerator = new PGPSignatureSubpacketGenerator();
            subPacketGenerator.setRevocable(true,true);
            subPacketGenerator.setSignatureCreationTime(true, new Date());
            PGPSignatureSubpacketVector packetVector = subPacketGenerator.generate();
            signatureGenerator.setHashedSubpackets(packetVector);
            PGPSignature signature = signatureGenerator.generateCertification(keyToBeRevoked);
            return signature;
        }catch(Exception x){
            Log.d(TAG,"getKeyCertification error",x );
            return null;
        }
 }
}
