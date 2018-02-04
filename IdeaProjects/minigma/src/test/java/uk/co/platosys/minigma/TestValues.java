package uk.co.platosys.minigma;

import java.io.File;

/**
 * Class containing a set of values to be used by the the various tests
 */
public class TestValues {
    static File testRoot = new File("/home/edward/platosys/test/minigma");
    static File keyDirectory = new File(testRoot,"keys");
    static File lockDirectory=new File(testRoot, "lockstore");
    static String testText = "Phlebas the Phoenician, a fortnight dead, " +
            "forgot the cry of gulls and the deep sea swell";
    static File cipherDirectory=new File (testRoot, "ciphertext");
    static File clearDirectory=new File (testRoot, "cleartext");
    static File signatureDirectory = new File (testRoot, "signatures");
    static File lockFile=new File(lockDirectory, "lockstore");
    static File clearFile=new File(clearDirectory, "cleartext");
    //File cipherFile= new File (cipherDirectory, "ciphertext");



    static String[] testUsernames={"testUser0", "testUser1", "testUser2", "testUser3","testUser4","testUser5","testUser6","testUser7", "testUser8", "testUser9"} ;
    static String[] testPassPhrases={"ABCDEFG", "BCDEFGH", "CDEFGHI", "DEFGHIJ", "EFGHIJK", "FGHIJKL", "GHIJKLM", "HIJKLMN", "IJKLMNO", "JKLMNOP"};
    static String[] testNotationNames={"Notation0", "Notation1", "Notation2", "Notation3", "Notation4"};
    static String[] testNotationValues={"value0", "value1", "value2", "value3", "value4"};
}
