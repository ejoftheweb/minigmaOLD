/*
 * Created 9 Dec 2016
 * www.platosys.co.uk 
 */
package uk.co.platosys.minigma;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.exceptions.SignatureException;
import uk.co.platosys.minigma.exceptions.UnsupportedAlgorithmException;
import uk.co.platosys.minigma.utils.MinigmaUtils;
import uk.co.platosys.minigma.CryptoEngine;
import uk.co.platosys.minigma.Key;
import uk.co.platosys.minigma.Lock;
import uk.co.platosys.minigma.LockStore;

/**
 * @author edward

 */
public class Minigma {
    public static String TAG = "Minigma";
    public  static final String PROVIDER_NAME = "BC";
    public static final int  HASH_ALGORITHM = HashAlgorithmTags.SHA512;
    public  static final int  COMPRESS_ALGORITHM = CompressionAlgorithmTags.UNCOMPRESSED;
    public static final int  STRONG_ALGORITHM = SymmetricKeyAlgorithmTags.AES_256;
    public static final int WEAK_ALGORITHM=SymmetricKeyAlgorithmTags.TRIPLE_DES;
    public static final Provider PROVIDER = initialiseProvider();
    public static final String LOCK_DIRNAME="lock";
    public static final String KEY_DIRNAME="key";
    public static final String VERSION="Minigma v0.1";

    /**
     * This takes an String and encrypts it with the given Lock
     * @param lock - the Lock with which to encrypt it;
     * @return
     * @throws MinigmaException
     */
    public static String lock(String clearString, Lock lock) throws MinigmaException{
        byte[] literalData=MinigmaUtils.toByteArray(clearString);
        byte[] compressedData = MinigmaUtils.compress(literalData);
        byte[] encryptedData= CryptoEngine.encrypt(compressedData, lock);
        return MinigmaUtils.encode(encryptedData);

    }

    /** This takes an EncryptedData String and returns  the cleartext
     * @return
     * @throws Exception
     */
    public static String unlock(String ciphertext, Key key, char[] passphrase) throws Exception {
        byte[] bytes = MinigmaUtils.decode(ciphertext);
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        return new String(CryptoEngine.decrypt(bais, key, passphrase), "UTF-8");
    }






    //Private methods



    protected static Provider initialiseProvider(){
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        return provider;
    }



}

