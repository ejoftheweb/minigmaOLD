package uk.co.platosys.minigma;

import org.junit.Test;
import uk.co.platosys.minigma.utils.Kidney;

import java.io.File;
import java.util.List;

import static junit.framework.TestCase.assertTrue;

public class KidneyTest {
    File testRoot = new File("/home/edward/platosys/test/minigma");
    File keyDirectory = new File(testRoot,"keys");
    File lockDirectory = new File(testRoot, "lockstore");
    File lockFile = new File(lockDirectory, "lockstore");
    String[] testUsernames={"testUser0", "testUser1", "testUser2", "testUser3","testUser4","testUser5","testUser6","testUser7", "testUser8", "testUser9"} ;
    String[] testPassPhrases={"ABCDEFG", "BCDEFGH", "CDEFGHI", "DEFGHIJ", "EFGHIJK", "FGHIJKL", "GHIJKLM", "HIJKLMN", "IJKLMNO", "JKLMNOP"};

    @Test
    public void fingerprintTest(){
        assertTrue(Kidney.EVEN_BIOMES.length==Kidney.ODD_BIOMES.length);
        try {
            MinigmaLockStore lockStore = new MinigmaLockStore(lockFile, false);
            //System.out.println(lockStore.getCount());
            Lock lock = lockStore.getLock(testUsernames[4]);

            byte[] fingerprint = lock.getFingerprint();
            //System.out.println(Kidney.toString(fingerprint));
            //System.out.println(fingerprint.length);
            List<String> fingerprintWords = Kidney.getFingerprint(fingerprint);
            System.out.println(fingerprintWords.size());
            for (String fingerprintWord : fingerprintWords) {
                System.out.println(fingerprintWord);
            }
        }catch(Exception x){
            System.out.println(x.getClass()+"\n"+x.getMessage());
        }
    }
}
