package uk.co.platosys.minigma;

import org.junit.Test;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.utils.Kidney;

import java.io.File;
import java.util.Iterator;
import java.util.List;

public class LockStoreTest {

    File testRoot = new File("/home/edward/platosys/test/minigma");
    File keyDirectory = new File(testRoot,"keys");
    File lockDirectory=new File(testRoot, "locks");
    File lockStoreDirectory = new File(testRoot, "lockstore");
    File lockStoreFile = new File(lockStoreDirectory, "lockstore");
    File lockFile = new File(lockDirectory, "ejofat");
    @Test
    public void loadLockStore(){
        LockStore lockStore=null;
        try {
            lockStore = new MinigmaLockStore(lockStoreFile, false);
            System.out.println("Loaded lockstore with "+lockStore.getCount()+" locks");
            Lock lock = new Lock(lockFile);
            lockStore.addLock(lock);
            //System.out.println("Added a lock so it now has "+lockStore.getCount()+" locks");
            System.out.println(Kidney.toString(lock.getLockID()));
            List<String> fingerprint = lock.getFingerprint().getFingerprint();
            for(String word:fingerprint){
                System.out.println(word);
            }
        }catch(MinigmaException mex){
            System.out.println(mex.getClass().getName()+"\n"+mex.getMessage());
        }

    }
}
