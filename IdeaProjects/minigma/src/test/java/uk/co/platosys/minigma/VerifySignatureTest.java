package uk.co.platosys.minigma;

import org.junit.Test;
import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.utils.Kidney;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class VerifySignatureTest {
    @Test
    public void verifySignatureTest(){
        Key key=null;
        Lock lock=null;
        File signatureFile=null;
        LockStore lockStore=null;
        try {
            lockStore = new MinigmaLockStore(new File(TestValues.lockDirectory, "lockstore"), false);
        }catch (MinigmaException e){
            System.out.println("VST1 "+e.getClass().getName()+"\n "+ e.getMessage());
            StackTraceElement[] stackTraceElements = e.getStackTrace();
            for (StackTraceElement stackTraceElement:stackTraceElements){
                System.out.println(stackTraceElement.toString());
            }
        }

        try {
            key = new Key(new File(TestValues.keyDirectory, TestValues.testUsernames[0]));
            Signature signature = key.sign(TestValues.testText, TestValues.testPassPhrases[0].toCharArray(),lockStore);
            System.out.println(Kidney.toString(signature.getKeyID())+":"+signature.getShortDigest());
            signatureFile = new File(TestValues.signatureDirectory, signature.getShortDigest());
            if (signatureFile.exists()) {
                signatureFile.delete();
            }
            signature.encodeToFile(signatureFile);
            lock = lockStore.getLock(TestValues.testUsernames[0]);
            //System.out.println(Kidney.toString(lock.getLockID()));
        }catch(Exception e) {

            System.out.println("VST2 "+e.getClass().getName()+"\n "+ e.getMessage());
            StackTraceElement[] stackTraceElements = e.getStackTrace();
            for (StackTraceElement stackTraceElement:stackTraceElements){
                System.out.println(stackTraceElement.toString());
            }
        }try{
            Signature rereadSignature = new Signature(signatureFile);
            //System.out.println(Kidney.toString(rereadSignature.getKeyID()));

            assertTrue(lock.verify(TestValues.testText,rereadSignature));
        }catch (Exception e){
            System.out.println("VST3 "+ e.getMessage());
            StackTraceElement[] stackTraceElements = e.getStackTrace();
            for (StackTraceElement stackTraceElement:stackTraceElements){
                System.out.println(stackTraceElement.toString());
            }
        }
    }
    @Test
    public void verifySignatureNotationsTest(){
        Key key=null;
        Lock lock=null;
        File signatureFile=null;
        LockStore lockStore=null;
        try {
            lockStore = new MinigmaLockStore(new File(TestValues.lockDirectory, "lockstore"), false);
        }catch (MinigmaException e){
            Exceptions.dump(e);
        }

        try {
            key = new Key(new File(TestValues.keyDirectory, TestValues.testUsernames[0]));
            List<Notation> notationList = new ArrayList<>();
            for (int i=0; i<TestValues.testNotationNames.length; i++){
                Notation notation = new Notation(TestValues.testNotationNames[i], TestValues.testNotationValues[i]);
                notationList.add(notation);
            }
            Signature signature = key.sign(TestValues.testText, notationList, TestValues.testPassPhrases[0].toCharArray(),lockStore);
            System.out.println(Kidney.toString(signature.getKeyID())+":"+signature.getShortDigest());
            signatureFile = new File(TestValues.signatureDirectory, signature.getShortDigest());
            if (signatureFile.exists()) {
                signatureFile.delete();
            }
            signature.encodeToFile(signatureFile);
            lock = lockStore.getLock(TestValues.testUsernames[0]);
            //System.out.println(Kidney.toString(lock.getLockID()));
        }catch(Exception e) {
            Exceptions.dump(e);
        }try{
            Signature rereadSignature = new Signature(signatureFile);
            List<String> notations = rereadSignature.getNotations();
            for(String notationName:notations){
                String notationValue = rereadSignature.getNotationValue(notationName);
                System.out.println(notationName + ":"+notationValue);
            }

            assertTrue(lock.verify(TestValues.testText,rereadSignature));
        }catch (Exception e){
           Exceptions.dump(e);
        }
    }
}
