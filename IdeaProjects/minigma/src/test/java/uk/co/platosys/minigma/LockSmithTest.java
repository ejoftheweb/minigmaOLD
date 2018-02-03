package uk.co.platosys.minigma;

import org.junit.Test;
import uk.co.platosys.minigma.exceptions.DuplicateNameException;
import uk.co.platosys.minigma.utils.FileTools;
import static org.junit.Assert.*;

import java.io.File;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class LockSmithTest {
    File testRoot = new File("/home/edward/platosys/test/minigma");
    File keyDirectory = new File(testRoot,"keys");
    File lockDirectory = new File(testRoot, "lockstore");
   String[] testUsernames={"testUser0", "testUser1", "testUser2", "testUser3","testUser4","testUser5","testUser6","testUser7", "testUser8", "testUser9"} ;
   String[] testPassPhrases={"ABCDEFG", "BCDEFGH", "CDEFGHI", "DEFGHIJ", "EFGHIJK", "FGHIJKL", "GHIJKLM", "HIJKLMN", "IJKLMNO", "JKLMNOP"};
    String testText = "Phlebas the Phoenician, a fortnight dead, " +
            "forgot the cry of gulls and the deep sea swell";
    File cipherDirectory=new File (testRoot, "ciphertext");
    File clearDirectory=new File (testRoot, "cleartext");
    LockStore lockStore;
    @Test
    public void createMultipleLockSetTest(){
        System.out.println("Running CreateMultipleLockset Test (CMLT)");
        testRoot.mkdirs();
        keyDirectory.mkdirs();
        lockDirectory.mkdirs();
        boolean duplicateName=false;
         File lockFile = new File(lockDirectory, "lockstore");

        try {
           lockStore = new MinigmaLockStore(lockFile, true);
           for (int i=0; i<testUsernames.length; i++) {
               File keyFile = new File(keyDirectory, FileTools.removeFunnyCharacters(testUsernames[i]));
               try {
                   long startTime=System.currentTimeMillis();
                   LockSmith.createLockset(keyDirectory, lockStore, testUsernames[i], testPassPhrases[i].toCharArray(), Algorithms.RSA);
                   long endTime=System.currentTimeMillis();
                   long takenTime=endTime-startTime;




                   System.out.println("CMLT created lockset for "+testUsernames[i] + " in "+takenTime+ "ms");

               }catch(DuplicateNameException dnx){
                   System.out.println(dnx.getMessage());
               }
           }
        }catch(Exception e){
            System.out.println(e.getMessage());
            System.out.println(e.getCause().getMessage());

        }

        assertTrue(lockFile.exists());
        for (int i=0; i<testUsernames.length; i++){
            assertTrue(lockStore.contains(testUsernames[i]));
        }

    }

}
