package uk.co.platosys.minigma.utils;
/*
//Version of MinigmaUtils for Android, uses the Android Base64 library rather than the standard Java one. c
 //in the JDK implementation of Minigma, this file does nothing and is commented out because of its
 //Android dependendencies
import android.util.Base64;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import uk.co.platosys.dinigma.Minigma;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.Date;

public class MinigmaUtilsA {

    static PGPCompressedDataGenerator compressor = new PGPCompressedDataGenerator(Minigma.COMPRESS_ALGORITHM);
    static PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
    static final int B64 =(Base64.URL_SAFE+Base64.NO_WRAP);
    static final String TAG = "MinigmaUtils";
    /** turns a byte array into a Base-64 encoded string **/
   /* public static String encode(byte[] bytes){
        return Base64.encodeToString(bytes, B64);
    }
    /** turns a base-64 encoded string into a byte array */
    /*public static byte[] decode(String string){
        return Base64.decode(string, B64);
    }
    /**converts an org.jdom2.Document into an array of bytes**/
   /* public static byte[] toByteArray(String string){
        return string.getBytes(Charset.forName("UTF-8"));
    }
    /**converts an array of bytes into a String*/
   /* public static String fromByteArray(byte[] asBytes){
        return new String(asBytes, Charset.forName("UTF-8"));
    }
    /**compresses a byte array of clear data
     * @param clearData a byte-array of clear, uncompressed data
     * @return a byte-array of clear, compressed data
     * */
    /*public static byte[] compress(byte[] clearData){
        printBytes(clearData);
        try {
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            OutputStream compressedOut = compressor.open(byteOut);
            OutputStream  literalOut = literalDataGenerator.open(compressedOut,
                    PGPLiteralData.BINARY,
                    "compressed",
                    clearData.length,
                    new Date());

            literalOut.write(clearData);
            literalOut.close();

            byte[] bytesOut = byteOut.toByteArray();
            printBytes(bytesOut);
            return bytesOut;
        }catch (IOException e){
            // TODO Auto-generated catch block
            Log.d(TAG,"error:",e);
            return null;
        }

    }
    public static void printBytes (byte[] bytes){
        for (byte byt:bytes){
            System.out.print(byt);
        }
        System.out.print("\n");
    }
}*/