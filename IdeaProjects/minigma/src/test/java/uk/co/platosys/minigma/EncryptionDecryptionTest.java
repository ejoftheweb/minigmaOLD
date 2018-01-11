package uk.co.platosys.minigma;

import org.junit.Test;
import uk.co.platosys.minigma.utils.MinigmaUtils;

import java.io.File;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;
import static uk.co.platosys.minigma.TestValues.clearFile;

public class EncryptionDecryptionTest {
    @Test
    public void encryptionDecryptionTest(){
        Key key=null;
        Lock lock=null;
        for (int i=0; i<TestValues.testUsernames.length; i++) {
            try {
                //The Lock we are going to encrypt the data with)
                lock = new MinigmaLockStore(TestValues.lockFile, false).getLock(TestValues.testUsernames[i]);

                //The data we are going to encrypt
                byte[] clearbytes = MinigmaUtils.readFromBinaryFile(clearFile);
                byte[] cipherText = lock.lock(clearbytes);
                String shortDigest = Digester.shortDigest(cipherText);
                File cipherFile = new File(TestValues.cipherDirectory, shortDigest);
                MinigmaUtils.encodeToArmoredFile(cipherFile, cipherText);
                //that's it saved. Now to undo it.

                key = new Key(new File(TestValues.keyDirectory, TestValues.testUsernames[i]));
                byte[] readCipherText = MinigmaUtils.readFromArmoredFile(cipherFile);
                byte[] decryptedBytes = key.unlockAsBytes(readCipherText, TestValues.testPassPhrases[i].toCharArray());
                assertTrue(Arrays.equals(clearbytes, decryptedBytes));
                //MinigmaUtils.writeToBinaryFile(new File(clearDirectory, "decrypted"), decryptedBytes);
                System.out.println("Encryption/decryption test OK on iteration "+i);
            } catch (Exception e) {
                System.out.println("BZ "+e.getClass().getName()+"\n "+ e.getMessage());
                //System.out.println("caused by "+e.getCause().getClass().getName()+":"+e.getCause().getMessage());
                StackTraceElement[] stackTraceElements = e.getStackTrace();
                for (StackTraceElement stackTraceElement:stackTraceElements){
                    System.out.println(stackTraceElement.toString());
                }
            }
        }
    }
}
