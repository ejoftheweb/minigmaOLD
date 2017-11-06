/*
 * The LockSmith, as the name suggests, makes Locks and matching keys which it saves
 * as PGP ascii-armored keyring files in the keys directory.
 * 
 * **YOUSAYWHO-specific features**
 * 1: the seedring
 * It saves two copies of the public key ring, one called "seedring".
 * Seedring shouldn't be written to once created; it's a shell for creating new public key rings 
 * in which the public key has no certification.
 * 
 * 2: the server's ring
 * if the attribute "first" is true, LockSmith creates an additional pair of public key rings in the 
 * server's key directory.
 * 
 * 
 * 
 */
package uk.co.platosys.dinigma;
import android.text.InputFilter;
import android.text.Spanned;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import uk.co.platosys.dinigma.exceptions.MinigmaException;
import uk.co.platosys.dinigma.utils.FileTools;
/**
 * @author edward
 * This is a key-pair generator - it has one method which generates a pair of keys and writes them to file.
 * Note that in fact it generates two key pairs: one for encryption, and one for signatures.
 * But they have the same passphrase.
 */
public class LockSmith {
	private static String PROVIDER="SC";
	static final String SIGNATURE_ALGORITHM = "DSA";
	static final String ASYMMETRIC_ALGORITHM="ELGAMAL";
    static final int SIGNATURE_ALGORITHM_TAG=PublicKeyAlgorithmTags.DSA;     
	
	/**
	 * 
	 * @param keyDirectory the directory in which the private key is to be saved. This could be on a removable drive.
	 * @param lockDirectory the directory in which the Lock(the public key) is to be saved.
	 * @param userName
	 * @param passPhrase
	 * @return The key_id of the signing key.
	 * @throws MinigmaException
	 */
	public static long createLockset(File keyDirectory, File lockDirectory, String userName, char[] passPhrase) throws MinigmaException {
		String filename;
		File lockFile;
		File keyFile;
		//test that parameters have been set:
		if (keyDirectory==null){
			throw new MinigmaException("Locksmith - key directory is null");
		}if (!keyDirectory.isDirectory()){
			throw new MinigmaException("Locksmith: "+keyDirectory.toString()+" is not a directory");
		}if (!keyDirectory.canWrite()){
			throw new MinigmaException("Locksmith: can't  write to "+keyDirectory.toString());
		}if (lockDirectory==null){
			throw new MinigmaException("Locksmith - lock directory is null");
		}if (!lockDirectory.isDirectory()){
			throw new MinigmaException("Locksmith: "+keyDirectory.toString()+" is not a directory");
		}if (!lockDirectory.canWrite()){
			throw new MinigmaException("Locksmith: can't  write to "+keyDirectory.toString());
		}
		try {
			if (Security.getProvider(PROVIDER)==null){
				Security.addProvider(new BouncyCastleProvider());
			}
		}catch(Exception e){
			throw new MinigmaException("Locksmith: problem adding security provider", e);
		}
		//
		KeyPairGenerator generator;
		KeyPair dsaKeyPair;
		KeyPair elgKeyPair;
        BigInteger g;
		BigInteger p;
		File lockFolder;
		File keyFolder;
		PGPKeyPair pgpSigKeyPair;
		PGPKeyPair pgpEncKeyPair;
		PGPKeyRingGenerator pgpKeyRingGenerator;
        PGPPublicKeyRing pgpPublicKeyRing;
        PGPSecretKeyRing pgpSecretKeyRing;
		try {
			//the DSA key for signing
            generator= KeyPairGenerator.getInstance(SIGNATURE_ALGORITHM, PROVIDER);
			generator.initialize(1024);
			dsaKeyPair = generator.generateKeyPair();
		}catch(Exception e){
			throw new MinigmaException("Locksmith: failed to generate dsa key pair", e);
		}
		try{
			//the strong ElGamal key for encrypting
			generator=KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM, PROVIDER);
			g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
            p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
            AlgorithmParameterSpec elGamalParameters = new ElGamalParameterSpec(p, g);
            generator.initialize(elGamalParameters);
            elgKeyPair=generator.generateKeyPair();
		}catch(Exception e){
			throw new MinigmaException("Locksmith: failed to generate elgamal key pair", e);
		}
        
		try{

            filename=FileTools.removeFunnyCharacters(userName);
            lockFolder=new File(lockDirectory, Minigma.LOCK_DIRNAME);
            if(!lockFolder.exists()){
                if(!lockFolder.mkdirs()){
                    throw new MinigmaException("Can't create lock folder");
                }
            }
            lockFile = new File(lockFolder, filename);
            if(lockFile.exists()){throw new MinigmaException("lockfile with name "+lockFile.getName()+" already exists");}
            keyFolder=new File(keyDirectory, Minigma.KEY_DIRNAME);
            if(!keyFolder.exists()){
                if(!keyFolder.mkdirs()){
                    throw new MinigmaException("Can't create key folder");
                }
            }
            keyFile = new File(keyFolder, filename);
            if(lockFile.exists()){throw new MinigmaException("keyfile with name "+keyFile.getName()+" already exists");}
           
    	}catch(Exception exc){
			throw new MinigmaException("Locksmith: error setting up key files", exc);
		}try{
            pgpSigKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKeyPair, new Date());
		}catch(Exception e){
			throw new MinigmaException("Locksmith: failed to generate pgp-dsa key pair", e);
		}try{
            pgpEncKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKeyPair, new Date());
		}catch(Exception e){
			throw new MinigmaException("Locksmith: failed to generate pgp-elgamal key pair", e);
		}
		PGPDigestCalculator pgpDigestCalculator=null;
		PGPContentSignerBuilder pgpContentSignerBuilder=null;
		PBESecretKeyEncryptor pbeSecretKeyEncryptor=null;
		try{
			pgpDigestCalculator = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
			pgpContentSignerBuilder = new JcaPGPContentSignerBuilder(SIGNATURE_ALGORITHM_TAG, HashAlgorithmTags.SHA512);
			pbeSecretKeyEncryptor = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, pgpDigestCalculator)
		        .setProvider(PROVIDER).build(passPhrase);
		}catch(Exception e){
			throw new MinigmaException("failed to initialise KRG components", e);
		}try{
			pgpKeyRingGenerator = new PGPKeyRingGenerator(
									PGPSignature.POSITIVE_CERTIFICATION, //certification level
									pgpSigKeyPair, //master key
									userName, // id
									pgpDigestCalculator,//PGPDigestCalculator
									null,//PGPSignatureSubpacketsVector hashed packets
									null,//PGPSignatureSubpacketsVector unhashed packets
									pgpContentSignerBuilder,//PGPContentSignerBuilder
									pbeSecretKeyEncryptor//PBESecretKeyEncryptor
									);
			
		}catch(PGPException e){
			throw new MinigmaException("Locksmith: failed to create PGP-keyring generator", e);
        }try{
            pgpKeyRingGenerator.addSubKey(pgpEncKeyPair);
        }catch(Exception e){
			throw new MinigmaException("Locksmith: failed to add elgamal subkey to ring", e);
		}try{
			ArmoredOutputStream secOut= new ArmoredOutputStream(new FileOutputStream(keyFile));
            pgpSecretKeyRing=pgpKeyRingGenerator.generateSecretKeyRing();
            pgpSecretKeyRing.encode(secOut);
            secOut.close();
        }catch(Exception e){
        	throw new MinigmaException("Locksmith: failed to encode secret key output", e);
		}try{
			 ArmoredOutputStream pubOut= new ArmoredOutputStream(new FileOutputStream(lockFile));
             pgpPublicKeyRing = pgpKeyRingGenerator.generatePublicKeyRing();
             pgpPublicKeyRing.encode(pubOut);
             pubOut.close();
             
        }catch (Exception e){
        	throw new MinigmaException("Locksmith: failed to encode pubring output",e);
		}
		
	return pgpSigKeyPair.getKeyID();
		
	}
 
	
        
       
}
