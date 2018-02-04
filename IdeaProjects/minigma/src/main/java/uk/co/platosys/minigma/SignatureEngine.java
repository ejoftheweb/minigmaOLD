
        package uk.co.platosys.minigma;



        import java.io.ByteArrayInputStream;
        import java.io.ByteArrayOutputStream;
        import java.io.InputStream;
        import java.security.Security;
        import java.util.ArrayList;
        import java.util.Date;
        import java.util.List;
        import org.bouncycastle.jce.provider.BouncyCastleProvider;
        import org.bouncycastle.openpgp.*;
        import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
        import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
        import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
        import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
        import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
        import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
        import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
        import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
        import uk.co.platosys.minigma.Key;
        import uk.co.platosys.minigma.Lock;
        import uk.co.platosys.minigma.Minigma;
        import uk.co.platosys.minigma.exceptions.Exceptions;
        import uk.co.platosys.minigma.exceptions.MinigmaException;
        import uk.co.platosys.minigma.utils.Kidney;
        import uk.co.platosys.minigma.utils.MinigmaUtils;


/**
 *
 * @author edward
 */
public class SignatureEngine {
    private static String TAG ="SignatureEngine";



    protected static Signature sign(String string, Key key, char [] passphrase, LockStore lockStore) throws MinigmaException{
        byte[] bytes = MinigmaUtils.toByteArray(string);
        return sign(bytes, key, passphrase, lockStore);
    }
    protected static Signature sign(String string, Key key, List<Notation> notations,  char [] passphrase, LockStore lockStore) throws MinigmaException{
        byte[] bytes = MinigmaUtils.toByteArray(string);
        return sign(bytes, key, notations, passphrase, lockStore);
    }
    protected static Signature sign(byte [] bytes, Key key, char[] passphrase, LockStore lockStore) throws MinigmaException{
        try{
            if(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)==null){
                Security.addProvider(new BouncyCastleProvider());
            }
            PBESecretKeyDecryptor keyDecryptor =  new JcePBESecretKeyDecryptorBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passphrase);
            PGPPrivateKey privateKey = key.getSigningKey().extractPrivateKey(keyDecryptor);
            PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(key.getSigningKey().getPublicKey().getAlgorithm(), Minigma.HASH_ALGORITHM);
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
            signatureGenerator.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey);
            PGPSignature pgpSignature = signatureGenerator.generate();
            pgpSignature.update(bytes, 0, 0);
            return new Signature(pgpSignature, lockStore.getUserID(key.getKeyID()) );

        }catch(Exception e){
             throw new MinigmaException("error making signature", e);
        }
    }
    protected static Signature sign(byte [] bytes, Key key, List<Notation> notations, char[] passphrase, LockStore lockStore) throws MinigmaException{
        try{
            if(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)==null){
                Security.addProvider(new BouncyCastleProvider());
            }
            PBESecretKeyDecryptor keyDecryptor =  new JcePBESecretKeyDecryptorBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passphrase);
            PGPPrivateKey privateKey = key.getSigningKey().extractPrivateKey(keyDecryptor);
            PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(key.getSigningKey().getPublicKey().getAlgorithm(), Minigma.HASH_ALGORITHM);
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
            signatureGenerator.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey);
            PGPSignatureSubpacketGenerator pgpSignatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
            for (Notation notation:notations){
                pgpSignatureSubpacketGenerator.setNotationData(notation.isCritical(), notation.isHumanReadable(), notation.getName(), notation.getValue());
            }
            PGPSignatureSubpacketVector pgpSignatureSubpacketVector = pgpSignatureSubpacketGenerator.generate();
            signatureGenerator.setHashedSubpackets(pgpSignatureSubpacketVector);
            PGPSignature pgpSignature = signatureGenerator.generate();
            pgpSignature.update(bytes, 0, 0);
            return new Signature(pgpSignature, lockStore.getUserID(key.getKeyID()) );

        }catch(Exception e){
            throw new MinigmaException("error making signature", e);
        }
    }

    protected static List<List<Fingerprint>> verify(String string, Signature signature, Lock lock){
        return verify(MinigmaUtils.toByteArray(string), signature, lock);
    }
    static List <List<Fingerprint>> verify(byte [] bytes, Signature signature, Lock lock){
        List<Fingerprint> signors = new ArrayList<Fingerprint>();
        List<Fingerprint> nonsignors=new ArrayList<Fingerprint>();
        List<List<Fingerprint>> results = new ArrayList<List<Fingerprint>>();
        results.add(signors);
        results.add(nonsignors);
        try{
            KeyFingerPrintCalculator calculator = new JcaKeyFingerprintCalculator();
            byte [] sigVal = signature.getBytes();
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

            for(int i=0; i<signatureList.size(); i++){
                PGPSignature pgpSignature = signatureList.get(i);
                long  keyID = pgpSignature.getKeyID();
                PGPPublicKey publicKey = lock.getPublicKey(keyID);
                PGPContentVerifierBuilderProvider pgpContentVerifierBuilder = new JcaPGPContentVerifierBuilderProvider();//.get(keyAlgorithm, Minigma.HASH_ALGORITHM);
                pgpSignature.init(pgpContentVerifierBuilder, publicKey);
                pgpSignature.update(bytes, 0,0);
                if(pgpSignature.verify()){
                   signors.add(new Fingerprint(publicKey.getFingerprint()));
                }else{
                   nonsignors.add(new Fingerprint(publicKey.getFingerprint()));
                }
            }
        }catch(Exception x){
           Exceptions.dump(x);
        }
        return results;
    }

    public static PGPSignature getKeyCertification(Key key, char[] passphrase, PGPPublicKey keyToBeSigned){

        try{
            if(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)==null){
                Security.addProvider(new BouncyCastleProvider());
            }
            PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(key.getSigningKey().getPublicKey().getAlgorithm(), Minigma.HASH_ALGORITHM);
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
            PGPSignatureSubpacketGenerator subPacketGenerator = new PGPSignatureSubpacketGenerator();
            subPacketGenerator.setRevocable(true,true);
            subPacketGenerator.setSignatureCreationTime(true, new Date());
            PGPSignatureSubpacketVector packetVector = subPacketGenerator.generate();
            signatureGenerator.setHashedSubpackets(packetVector);
            JcePBESecretKeyDecryptorBuilder keyDecryptorBuilder = new JcePBESecretKeyDecryptorBuilder();
            keyDecryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            signatureGenerator.init(PGPSignature.POSITIVE_CERTIFICATION, key.getSigningKey().extractPrivateKey(keyDecryptorBuilder.build(passphrase)));
            PGPSignature signature = signatureGenerator.generateCertification(keyToBeSigned);
            return signature;
        }catch(Exception x){
            Exceptions.dump(x);
            return null;
        }
    }

    static PGPSignature getKeyRevocation(Key key, char [] passphrase, PGPPublicKey keyToBeRevoked){

        try{
            if(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)==null){
                Security.addProvider(new BouncyCastleProvider());
            }
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
            Exceptions.dump(x);
            return null;
        }
    }
}