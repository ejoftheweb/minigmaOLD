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

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPCompressedData;
import org.spongycastle.openpgp.PGPEncryptedDataGenerator;
import org.spongycastle.openpgp.PGPEncryptedDataList;
import org.spongycastle.openpgp.PGPLiteralData;
import org.spongycastle.openpgp.PGPObjectFactory;
import org.spongycastle.openpgp.PGPOnePassSignatureList;
import org.spongycastle.openpgp.PGPPrivateKey;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyEncryptedData;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPSecretKey;
import org.spongycastle.openpgp.PGPSignatureList;
import org.spongycastle.openpgp.PGPUtil;
import org.spongycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.spongycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.spongycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.spongycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.spongycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.spongycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import uk.co.platosys.dinigma.Key;
import uk.co.platosys.dinigma.Lock;
import uk.co.platosys.dinigma.Minigma;
import uk.co.platosys.dinigma.exceptions.DecryptionException;
import uk.co.platosys.dinigma.exceptions.MinigmaException;
import uk.co.platosys.dinigma.utils.MinigmaUtils;


/**
 * this  class holds the static decrypt and encrypt methods
 *
 * @author edward
 */
public  class CryptoEngine {
private static String TAG ="CryptoEngine";

/**
 *  Decrypts an InputStream to a Document
 * 
 * @param inputStream
 * @param key
 * @param passphrase
 * @return
 * @throws Exception 
 */

public static String decrypt(InputStream inputStream, Key key, char[] passphrase)throws Exception{
     	InputStream in;
    	PGPObjectFactory pgpObjectFactory;
    	PGPEncryptedDataList pgpEncryptedDataList=null;
    	PGPPrivateKey privateKey=null;
    	PGPPublicKeyEncryptedData pgpPublicKeyEncryptedData=null;
    	Object compressedObject=null;
    	PGPLiteralData literalData=null;
    	//First get a  PGPEncryptedDataList from the input stream.
    	try {
    		in = PGPUtil.getDecoderStream(inputStream);
    		pgpObjectFactory=new PGPObjectFactory (in, new JcaKeyFingerprintCalculator());
    			Object object = pgpObjectFactory.nextObject();
    			if (object instanceof PGPEncryptedDataList){
                                //the EncryptedDataList is either the first object;
    				pgpEncryptedDataList=(PGPEncryptedDataList) object;
    			}else{
                                //or the next
    				pgpEncryptedDataList=(PGPEncryptedDataList)pgpObjectFactory.nextObject();
    			}

    		if (pgpEncryptedDataList==null){
                    throw new MinigmaException("couldn't find encrypted data list");
                }
    	}catch (Exception e){
    		//Log.d(TAG,"Minigma-unLock() 1: error reading encrypted data list", e);
    		throw new MinigmaException("error reading encrypted data list", e);
    	}
    	// now get encrypted objects from the list.
    	try {
    		//Log.d(TAG, "Minigma-unLock() 2 start");
    		@SuppressWarnings("unchecked")
			Iterator<PGPPublicKeyEncryptedData> it = pgpEncryptedDataList.getEncryptedDataObjects();
    		//Log.d(TAG, "Minigma-unLock() 2: EncryptedDataList size = "+Integer.toString(pgpEncryptedDataList.size())+", now got its iterator");
    		JcePBESecretKeyDecryptorBuilder keyDecryptorBuilder =  new JcePBESecretKeyDecryptorBuilder();
	         keyDecryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
    		while(it.hasNext()&&privateKey==null){
    			pgpPublicKeyEncryptedData = it.next();
    			long keyID = pgpPublicKeyEncryptedData.getKeyID();
    			//Log.d(TAG, "Minigma-unLock() 2: data was encrypted with key:"+ Long.toHexString(keyID));
    			PGPSecretKey secretKey = key.getDecryptionKey(keyID);
                        if (secretKey==null){
                            //Log.d(TAG, "Minigma-unLock() 2: bad key, no decryption key");
                            throw new DecryptionException("2: bad key, no decryption key");
                        }
                        if (secretKey.getKeyID()==keyID){
    				privateKey = key.getDecryptionKey(keyID).extractPrivateKey(keyDecryptorBuilder.build(passphrase));
    		        //Log.d(TAG,"Minigma-unLock() 2: got private key");
    			}else{
    				//Log.d(TAG, "Engima-unLock() 2: not this time, round again.");
    			}
    		}
    		if (privateKey==null){

    			throw new DecryptionException("Minigma-unLock() 2: decryption key doesn't fit any of the locks");
    		}
    	}catch(Exception e){

    		throw e;
    	}
    	
    	try {

    		PublicKeyDataDecryptorFactory dataDecryptorFactory = new BcPublicKeyDataDecryptorFactory(privateKey);
    		InputStream decryptedStream=pgpPublicKeyEncryptedData.getDataStream(dataDecryptorFactory);
    		JcaPGPObjectFactory compressedFactory = new JcaPGPObjectFactory(decryptedStream);
    		compressedObject = compressedFactory.nextObject();

    	}catch(Exception e){

    		throw new MinigmaException("Minigma-unLock() 3: error reading encrypted data stream",e);
    	}
    	try {

    		PGPCompressedData clearCompressedData = (PGPCompressedData) compressedObject;
    		Object uncompressedObject=null;
    		JcaPGPObjectFactory uncompressedFactory=null;
    		try{
    			InputStream inputStream2 = clearCompressedData.getDataStream();
    			
    			
    			 uncompressedFactory = new JcaPGPObjectFactory(inputStream2);
    			
    		    uncompressedObject = uncompressedFactory.nextObject();
    		   
    		}catch(Exception x){
    			Log.d(TAG,"error",x);
    		}
    		Log.d(TAG,"uncompressed object class is "+uncompressedObject.getClass().getCanonicalName());
    		if (uncompressedObject instanceof PGPOnePassSignatureList ){
    				// and the next object should be literal data:
    				uncompressedObject = uncompressedFactory.nextObject();
    				if (uncompressedObject instanceof PGPLiteralData){
    					literalData=(PGPLiteralData) uncompressedObject;
    				}else{
    					//unrecognised object;
    					Log.d(TAG, "Minigma-unLock() 4: unrecognised object: A "+ uncompressedObject.getClass().getName());
       				return null;
    				}
    				uncompressedObject = uncompressedFactory.nextObject();
    				if (uncompressedObject instanceof PGPSignatureList){
    				}else{
    					//unrecognised object;
    					Log.d(TAG, "Minigma-unlock() 4: unrecognised object B "+ uncompressedObject.getClass().getName());
    				}
    			}else if (uncompressedObject instanceof PGPLiteralData){
    				Log.d(TAG, "Minigma-unlock() 4: unsigned literal data");
    				//it's unsigned, so the next object is just literal data.
    				literalData = (PGPLiteralData) uncompressedObject;
    			}else{
    				//unrecognised object
    				Log.d(TAG, "Minigma-unLock() 4: unrecognised object C "+ uncompressedObject.getClass().getName());
    				return null;
    			}
      }catch(Exception e){
    		Log.d(TAG, "Minigma-unLock() 4: error getting decompressed object", e );
    		return null;
    	}

      
     	InputStream inputStream1 = literalData.getDataStream();
     	ByteArrayOutputStream result = new ByteArrayOutputStream();
     	byte[] buffer = new byte[1024];
     	int length;
     	while ((length = inputStream1.read(buffer)) != -1) {
     	    result.write(buffer, 0, length);
     	}
     	return result.toString("UTF-8");
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
   	PGPEncryptedDataGenerator encryptedDataGenerator=configureGenerator(Minigma.STRONG_ALGORITHM,lock);
   	ByteArrayOutputStream encryptedByteStream = new ByteArrayOutputStream();
   	OutputStream outputStream = encryptedByteStream;
   	outputStream= new ArmoredOutputStream(outputStream);

   	try {
   		outputStream = encryptedDataGenerator.open(encryptedByteStream, compressedData.length);
   		outputStream.write(compressedData);
   		outputStream.flush();
   		outputStream.close();
   		byte[] encryptedBytes = encryptedByteStream.toByteArray();
   		MinigmaUtils.printBytes(encryptedBytes);
   		return encryptedBytes;
   	}catch(Exception e){
   		throw new MinigmaException("Minigma-encrypt: error encrypting with strong algorithm, trying a weaker one", e);
   	}
   }
   
private  static PGPEncryptedDataGenerator configureGenerator(int algorithm, Lock lock) throws MinigmaException {
       PGPEncryptedDataGenerator encryptedDataGenerator;

   	try{
   		PGPDataEncryptorBuilder dataEncryptorBuilder = new JcePGPDataEncryptorBuilder(algorithm);
   		encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptorBuilder);
   		Iterator<PGPPublicKeyRing> it = lock.getKeys();
   		if (!it.hasNext()){
   			throw new MinigmaException("Empty Lock: "+lock.toString());
   		}
   		while (it.hasNext()){
   			PGPPublicKeyRing keyRing = it.next();
            Iterator<PGPPublicKey> pubkit = keyRing.getPublicKeys();
            while(pubkit.hasNext()){
                PGPPublicKey key = pubkit.next();
                if(key.isEncryptionKey()){
                	PGPKeyEncryptionMethodGenerator methodGenerator = new JcePublicKeyKeyEncryptionMethodGenerator(key);	    
                    encryptedDataGenerator.addMethod(methodGenerator);

                }
            }
   		}
        return encryptedDataGenerator;
   	}catch(Exception e){
   		Log.d(TAG, "Minigma-encrypt: error configuring generator",e);
   		throw new MinigmaException("Minigma-encrypt: error configuring generator",e);
   	}
   }
}
