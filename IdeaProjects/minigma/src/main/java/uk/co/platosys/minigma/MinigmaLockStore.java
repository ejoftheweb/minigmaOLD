
/* Created on Jan 30, 2006
        * (c) copyright 2017 Platosys
        * MIT Licence
        
        * This is an implementation of the Lockstore interface that uses the OpenPGP public key ring format to store keys
        *
        *
        *
        */
        package uk.co.platosys.minigma;


        import java.io.File;
        import java.io.FileInputStream;
        import java.io.FileOutputStream;
        import java.io.InputStream;
        import java.io.OutputStream;
        import java.util.ArrayList;
        import java.util.Collection;
        import java.util.Iterator;
        import java.util.List;

        import org.bouncycastle.bcpg.ArmoredInputStream;
        import org.bouncycastle.bcpg.ArmoredOutputStream;
        import org.bouncycastle.openpgp.PGPPublicKey;
        import org.bouncycastle.openpgp.PGPPublicKeyRing;
        import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
        import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
        import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

        import uk.co.platosys.minigma.exceptions.MinigmaException;
        import uk.co.platosys.minigma.utils.MinigmaOutputStream;


/**
 * @author edward
 * The MinigmaLockStore implements the LockStore interface using  OpenPGP public keyrrings as the storage
 * medium. The file it creates is an OpenPGP public keyrring and can be read by other OpenPGP compliant software
 *
 *
 */
public class MinigmaLockStore implements LockStore {
    private static String TAG = "LockStore";
    private PGPPublicKeyRingCollection keyRings;
    private PGPPublicKeyRing pgpPublicKeyRing;
    private File file;
    private long storeId;
    private int count;

    /**
     *  Creates a MinigmaLockStore. Reads it in from a file; if the file doesn't exist, and create is true, it will
     *  create a new one. Otherwise it will throw an error.
     * @param file
     * @param create
     * @throws MinigmaException
     */
    public MinigmaLockStore(File file, boolean create) throws MinigmaException{
        this.file=file;
        if (file.exists()&&file.canRead()){
            if (!load()){
                throw new MinigmaException("LockStore-init failed at loading");
            }else{
                //System.out.println("MLS-loaded:"+count);
            }
        }else{
            if(create){
                Collection<PGPPublicKeyRing> ringCollection=new ArrayList<>();
                try {
                    this.keyRings = new PGPPublicKeyRingCollection(ringCollection);
                    save();
                }catch (Exception x){}
            }else{
                throw new MinigmaException( "LockStore-init: file doesn't exist");
            }
        }
    }

    private  boolean load() throws MinigmaException{
        try {
            InputStream keyIn = new ArmoredInputStream(new FileInputStream(file));
            KeyFingerPrintCalculator calculator = new JcaKeyFingerprintCalculator();
            keyRings=new PGPPublicKeyRingCollection(keyIn, calculator);
            PGPPublicKey publicKey = null;
            Iterator<PGPPublicKeyRing> ringIterator = keyRings.getKeyRings();
            while (ringIterator.hasNext() ){
                PGPPublicKeyRing thisKeyRing=ringIterator.next();
                Iterator<PGPPublicKey> keyIterator = thisKeyRing.getPublicKeys();
                while(keyIterator.hasNext() && publicKey==null){
                    PGPPublicKey testKey = keyIterator.next();
                    if (testKey.isEncryptionKey()){
                        publicKey=testKey;
                        pgpPublicKeyRing=thisKeyRing;

                    }
                }
                if(count==1){this.storeId=publicKey.getKeyID();}
                count++;
            }

            //encryptionLock=new Lock(publicKey);
            return true;
        }catch(Exception e){
            throw new MinigmaException ("Lockstore: load failed", e);
        }
    }
    private boolean save(){
        try {
            MinigmaOutputStream armoredOutputStream = new MinigmaOutputStream(new FileOutputStream(file));
            keyRings.encode(armoredOutputStream);
            armoredOutputStream.close();
            return true;
        }catch(Exception e){
             return false;
        }
    }

    public boolean saveAs(File file){
        this.file=file;
        return save();
    }

    @Override
    public boolean addLock(Lock lock){
        try {
            if (keyRings==null){
                load();
            }
            Iterator<PGPPublicKeyRing> it = lock.getKeys();

            while (it.hasNext()){
                PGPPublicKeyRing publicKey =  it.next();
                keyRings = PGPPublicKeyRingCollection.addPublicKeyRing(keyRings, publicKey);
                count++;
            }
            return save();
        }catch(Exception e){
            return false;
        }
    }

    /** @param keyID
     * @return a lock with this keyID */
    @Override
    public Lock getLock(long keyID){
        try{
            PGPPublicKeyRing keyRing = keyRings.getPublicKeyRing(keyID);
            Collection<PGPPublicKeyRing> collection = new ArrayList<>();
            collection.add(keyRing);
            PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(collection);
            return new Lock(keyRingCollection);
        }catch(Exception e){
            return null;
        }
    }
    @Override
    public Iterator<Lock> iterator() throws MinigmaException{
        List<Lock> list = new ArrayList<>();
        try{
            Iterator<PGPPublicKeyRing> kringit = keyRings.getKeyRings();
            while(kringit.hasNext()){
                Collection<PGPPublicKeyRing> collection = new ArrayList<>();
                collection.add(kringit.next());
                PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(collection);
                list.add(new Lock(keyRingCollection));
            }
        }catch(Exception e){
            throw new MinigmaException("problem creating lockstore iterator", e);
        }
        return list.iterator();
    }
    /** returns */
    @Override
    public Lock getLock(String userID)throws MinigmaException{
        try{
            PGPPublicKeyRingCollection keyRingCollection=null;
            Iterator<PGPPublicKeyRing> itr = keyRings.getKeyRings(userID, true);
            while(itr.hasNext() ){
                PGPPublicKeyRing publicKeyRing=itr.next();
                if (keyRingCollection==null){
                    Collection<PGPPublicKeyRing> collection = new ArrayList<>();
                    collection.add(publicKeyRing);
                    keyRingCollection=new PGPPublicKeyRingCollection(collection);
                }else{
                    keyRingCollection=PGPPublicKeyRingCollection.addPublicKeyRing(keyRingCollection,publicKeyRing);
                }
            }
            System.out.println("getting lock for "+userID);
            return new Lock(keyRingCollection);
        }catch(Exception e){
            throw new MinigmaException("error getting lock for userID "+userID, e);
        }
    }
    /**
     *
     */
    @Override
    public long getStoreId(){
        return storeId;
    }

    public boolean contains(String userID){
        try {
            Iterator<PGPPublicKeyRing> itr = keyRings.getKeyRings(userID);
            return itr.hasNext();
        }catch (Exception x){
            return false;
        }
    }
    public int getCount(){
        return count;
    }

}