package uk.co.platosys.minigma;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.Test;
import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.utils.Kidney;

import java.io.File;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static org.junit.Assert.assertTrue;

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
System.out.println("Running Certification Test");
        try {
            System.out.println("Running Certification Test (CT1)");
            LockStore lockstore = new MinigmaLockStore(TestValues.lockFile, false);
            System.out.println("CT1: lockstore size is "+lockstore.getCount());
            Map<String, Certificate> certificatesMap = new HashMap<>();
            for (String username:TestValues.testUsernames){
                System.out.println("CT1 testing lock for "+username);

                Lock lock =lockstore.getLock(username);
                int lockSize = lock.getBytes().length;
                System.out.println("CT1 "+username+" has lock "+Kidney.toString(lock.getLockID())+", size "+lockSize);

                for (int i=0; i<TestValues.testUsernames.length; i++){
                    String signername = TestValues.testUsernames[i];
                    Key key = new Key(new File(TestValues.keyDirectory, signername));
                    System.out.println("\tCT1 "+signername+ ",id:"+Kidney.toString(key.getKeyID())+" signing "+username+"'s lock, id:"+Kidney.toString(lock.getLockID()));

                    char[] passphrase = TestValues.testPassPhrases[i].toCharArray();
                    Iterator<PGPPublicKeyRing> publicKeyRingIterator = lock.getPGPPublicKeyRingIterator();
                    while(publicKeyRingIterator.hasNext()){
                        PGPPublicKeyRing pgpPublicKeyRing = publicKeyRingIterator.next();
                        Iterator<PGPPublicKey> publicKeyIterator = pgpPublicKeyRing.getPublicKeys();
                        while (publicKeyIterator.hasNext()){
                            PGPPublicKey pgpPublicKey = publicKeyIterator.next();
                            Certificate certificate = lock.certify(pgpPublicKey.getKeyID(), key, passphrase);
                            System.out.println("\t\tCT1 Certificate "+certificate.getShortDigest()+" signed by "+Kidney.toString(certificate.getKeyID()));
                            int certSize = certificate.getBytes().length;
                            certificatesMap.put(certificate.getShortDigest(), certificate);
                            System.out.println("\t\tCT1 Certificate size is:"+certSize+", and there are "+certificatesMap.size()+" certs in collection");
                        }
                    }

                }
                if(lockstore.addLock(lock)){
                    System.out.println("\tCT1: newly signed lock added to lockstore");
                }
                System.out.println("\tCT1: newly signed locksize is "+lock.getBytes().length);
                System.out.println("\tCT1 "+certificatesMap.size()+" certs in collection");
            }
            System.out.println("CT1 "+certificatesMap.size()+" certs in collection");
            System.out.println("Running Certification Test CT2");
            for (String username:TestValues.testUsernames){
                Lock lock = lockstore.getLock(username);
                System.out.println("CT2 testing certificates for "+username+"'s lock, id:"+Kidney.toString(lock.getLockID()));
                List<Certificate> certificates = lock.getCertificates();
                System.out.println("CT2 lock "+Kidney.toString(lock.getLockID())+" has "+certificates.size()+" certificates");
                for(Certificate certificate:certificates){
                    System.out.println("\tCT2 attached certificate on lock "+certificate.getShortDigest()+" was signed by "+Kidney.toString(certificate.getKeyID()));
                    try {
                        if(certificatesMap.containsKey(certificate.getShortDigest())) {
                            Certificate certificate1 = certificatesMap.get(certificate.getShortDigest());
                            System.out.println("\t CT2 certificate in collection "+certificate1.getShortDigest()+" was signed by "+Kidney.toString(certificate1.getKeyID()));
                            assertTrue(certificate.equals(certificate1));
                        }else{
                            System.out.println("\tCT2 certificate "+certificate.getShortDigest()+" not found in collection");
                        }


                    }catch(NullPointerException npe){
                        Exceptions.dump(npe);
                    }


                }

            }
        }catch(Exception x){
            Exceptions.dump(x);
        }
    }
}
