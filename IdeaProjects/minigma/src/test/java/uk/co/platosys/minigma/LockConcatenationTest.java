package uk.co.platosys.minigma;

import org.junit.Before;
import org.junit.Test;
import uk.co.platosys.minigma.exceptions.DuplicateNameException;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.utils.FileTools;
import uk.co.platosys.minigma.utils.Kidney;
import uk.co.platosys.minigma.utils.MinigmaUtils;

import java.io.File;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class LockConcatenationTest {



    @Test
    public void lockConcatenationTest(){
        try {
            //Create a concatenated Lock
            LockStore lockStore = new MinigmaLockStore(TestValues.lockFile, false);
            Lock lock = lockStore.getLock(TestValues.testUsernames[0]);
            for (int i = 1; i < TestValues.testUsernames.length; i++) {
                Lock newLock = lockStore.getLock(TestValues.testUsernames[i]);
                long newLockID = newLock.getPGPPublicKeyRingIterator().next().getPublicKey().getKeyID();
                Fingerprint fingerprint = newLock.getFingerprint();
                assertTrue(newLockID==fingerprint.getKeyID());
                lock = lock.addLock(newLock, false);
            }
            byte[] clearbytes = MinigmaUtils.readFromBinaryFile(TestValues.clearFile);
            byte[] cipherText = lock.lock(clearbytes);
            String shortDigest = Digester.shortDigest(cipherText);
            File cipherFile = new File(TestValues.cipherDirectory, shortDigest);
            MinigmaUtils.encodeToArmoredFile(cipherFile, cipherText);

            //
            for (int i = 0; i < TestValues.testUsernames.length; i++) {
                Key key = new Key(new File(TestValues.keyDirectory, TestValues.testUsernames[i]));
                byte[] readCipherText = MinigmaUtils.readFromArmoredFile(cipherFile);
                byte[] decryptedBytes = key.unlockAsBytes(readCipherText, TestValues.testPassPhrases[i].toCharArray());
                assertTrue(Arrays.equals(clearbytes, decryptedBytes));
                System.out.println("LCT test  OK on iteration "+i);
            }
        }catch(Exception e){

            System.out.println("LCT1 "+e.getClass().getName()+"\n "+ e.getMessage());
            StackTraceElement[] stackTraceElements = e.getStackTrace();
            for (StackTraceElement stackTraceElement:stackTraceElements){
                System.out.println(stackTraceElement.toString());
            }
        }
    }
}
