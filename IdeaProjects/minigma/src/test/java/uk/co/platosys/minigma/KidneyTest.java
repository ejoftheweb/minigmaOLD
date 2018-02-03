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
        assertTrue(Fingerprint.EVEN_BIOMES.length==Fingerprint.ODD_BIOMES.length);
        try {
            MinigmaLockStore lockStore = new MinigmaLockStore(lockFile, false);
            Lock lock = lockStore.getLock(testUsernames[4]);

            Fingerprint fingerprint = lock.getFingerprint();
            List<String> fingerprintWords = fingerprint.getFingerprint();
            System.out.println(fingerprintWords.size());
            for (String fingerprintWord : fingerprintWords) {
                System.out.println(fingerprintWord);
            }
        }catch(Exception x){
            System.out.println(x.getClass()+"\n"+x.getMessage());
        }
    }
}
