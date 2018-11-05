/*
 * Copyright Edward Barrow and Platosys.
 * This software is licensed under the Free Software Foundation's
General Public Licence, version 2 ("the GPL").
The full terms of the licence can be found online at http://www.fsf.org/

In brief, you are free to copy and to modify the code in any way you wish, but if you
publish the modified code you may only do so under the GPL, and (if asked) you must
 supply a copy of the source code alongside any compiled code.

Platosys software can also be licensed on negotiated terms if the GPL is inappropriate.
For further information about this, please contact software.licensing@platosys.co.uk
 */

package uk.co.platosys.minigma;




import java.io.IOException;
import java.nio.charset.Charset;

import net.openhft.hashing.LongHashFunction;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.openpgp.PGPSignature;
import uk.co.platosys.minigma.exceptions.Exceptions;
import uk.co.platosys.minigma.exceptions.MinigmaException;
import uk.co.platosys.minigma.utils.MinigmaUtils;


/**
 * a class with static methods for digesting elements, documents and
 * byte arrays.
 * @author edward
 */
public class Digester {
    private static String TAG ="Digester";
    public static byte[] bytesDigest (String string) throws MinigmaException{
        return bytesDigest(string.getBytes(Charset.forName("UTF-8")));
    }

    public static String digest (String string) throws MinigmaException{
        return MinigmaUtils.encode(bytesDigest(string.getBytes(Charset.forName("UTF-8"))));
    }
    /**Takes a byte array and returns a string which is
     * the Base64 encoded version the digest.
     * This uses SHA3-512 as the digest algorithm.
     *
     * */
    public static byte[] bytesDigest (byte[] bytes) throws MinigmaException{
        try {
            KeccakDigest digest = new SHA3Digest(512);
            for (byte byt : bytes) {
                digest.update(byt);
            }
            byte[] digested = new byte[digest.getDigestSize()];
            digest.doFinal(digested, 0);
            return digested;
        }catch(Exception e){
            throw new MinigmaException("error making digest", e);
            //return(MinigmaUtils.encode(digested));

        }
    }

    /**
     * This returns a short String which is a non-cryptographic hash of
     * the supplied byte array. The short hashes so obtained are used as identifiers
     * and filenames for Signatures.
     * @param bytes
     * @return
     * @throws MinigmaException
     */
    public static String shortDigest (byte[] bytes) {
        try{
            LongHashFunction longHashFunction = LongHashFunction.xx();
            long longHash = longHashFunction.hashBytes(bytes);
            return(MinigmaUtils.encode(longHash));
        }catch(Exception e){
            Exceptions.dump(e);
            return null;
        }
    }
    public static String shortDigest (PGPSignature signature) {
        try {
            return shortDigest(signature.getEncoded());
        }catch(IOException iox){
            Exceptions.dump(iox);
            return null;
        }
    }

}
