package uk.co.platosys.minigma;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;

import java.math.BigInteger;

public class Algorithms {

    public static final int RSA = 4;
    public static final int ELGAMAL=8;
    public static final int EC= 12;
    public static final int DSA=16;

    //String definitions
    public static final String RSAS="RSA";

    //Elgamal parameters
    public static BigInteger ELGAMAL_G = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    public static BigInteger ELGAMAL_P = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

    public static final int STANDARDS_HASH = HashAlgorithmTags.SHA1;
    public static final int STRONG_HASH = HashAlgorithmTags.SHA512;

    public static final int SYMMETRIC_ALGORITHM = PGPEncryptedData.AES_256;
}
