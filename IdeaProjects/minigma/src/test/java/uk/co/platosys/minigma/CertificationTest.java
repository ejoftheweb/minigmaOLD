package uk.co.platosys.minigma;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.Test;
import uk.co.platosys.minigma.exceptions.Exceptions;

import java.io.File;
import java.util.Iterator;

public class CertificationTest {
    @Test
    public void certificationTest(){
        //1.For each testuser 0-9
            // Get a lock and certify it by testusers 0-9.
            // Save it to the lockstore.
        ////
        //2. For each testuser 0-9
        //     Retrieve the lock and get its certifications;
        //      for each certification:
        //         verify the certificate signature
        //      //
             //

        try {
            LockStore lockstore = new MinigmaLockStore(TestValues.lockFile, false);
            for (String username:TestValues.testUsernames){
                Lock lock =lockstore.getLock(username);
                for (int i=0; i<TestValues.testUsernames.length; i++){
                    String signername = TestValues.testUsernames[i];
                    Key key = new Key(new File(TestValues.keyDirectory, signername));
                    char[] passphrase = TestValues.testPassPhrases[i].toCharArray();
                    Iterator<PGPPublicKeyRing> publicKeyRingIterator = lock.getKeys();
                    while(publicKeyRingIterator.hasNext()){
                        PGPPublicKeyRing pgpPublicKeyRing = publicKeyRingIterator.next();
                        Iterator<PGPPublicKey> publicKeyIterator = pgpPublicKeyRing.getPublicKeys();
                        while (publicKeyIterator.hasNext()){
                            PGPPublicKey pgpPublicKey = publicKeyIterator.next();
                            lock.certify(pgpPublicKey.getKeyID(), key, passphrase);
                        }
                    }

                }
                lockstore.addLock(lock);

            }
        }catch(Exception x){
            Exceptions.dump(x);
        }
    }
}
