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
package uk.co.platosys.minigma.utils;

import java.nio.ByteBuffer;
import java.nio.LongBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;


/**
 *
 *
 * Kidney is a utility providing static classes to convert a
 * PGP KeyID, or a fingerprint, to a string and back again.
 *
 * Additionally, it produces and expects strings which have colons, spaces or dashes at every
 * second character, to make the thing look prettier.
 *
 * The default separator is a dash, not a colon. The resultant strings therefore can  (but should not) be
 * used as xml attribute names.
 *
 */
public class Kidney {
    static final SecureRandom RANDOM=new SecureRandom();



    public static final char DEFAULT_SEPARATOR='-';
    static final char[] HEX_CHAR_TABLE = {
            '0', '1', '2', '3','4', '5', '6', '7','8', '9', 'a', 'b','c','d', 'e', 'f'
    };

    /**
     * Takes a long and returns a String, formatted as pairs of hexadecimal digits separated by dashes.
     * @param k
     * @return
     */
    public static String toString(long k){
       return toString(k, DEFAULT_SEPARATOR);
    }
    /**
     * takes a long and a char and returns a String, formatted as pairs of hexadecimal digits separated by the char.
     * @param k
     * @param separator
     * @return
     */
    public static String toString(long k, char separator){
        char[] sepchar = new char[1];
        sepchar[0]=separator;
        String unbrokenString = Long.toHexString(k);
        String brokenString="";
        for (int i=0; i<unbrokenString.length()-1; i=i+2){
            char [] x = new char[3];
            x[0] = unbrokenString.charAt(i);
            x[1] = unbrokenString.charAt(i+1);
            x[2] = sepchar[0];

            String newString = new String (x);
            brokenString = brokenString+newString;
        }
        if(brokenString.endsWith(new String(sepchar))){
            brokenString = brokenString.substring(0, (brokenString.length()-1));
        }
        return brokenString;
    }

    /**
     *
     * @param fingerprint
     * @return
     */
    public static String toString(byte[] fingerprint) {

        char separator='-';
        char[] hex = new char[(3 * fingerprint.length)-1];

        for (int i=0; i<((fingerprint.length)-1); i++) {
            byte b = fingerprint[i];
            int v = b & 0xFF;
            hex[(3*i)] = HEX_CHAR_TABLE[v >>> 4];
            hex[(3*i)+1]=HEX_CHAR_TABLE[v & 0xF];
            hex[(3*i)+2]=separator;
        }
        int i= (fingerprint.length-1);
        byte b = fingerprint[i];
        int v = b & 0xFF;
        hex[(3*i)] = HEX_CHAR_TABLE[v >>> 4];
        hex[(3*i)+1]=HEX_CHAR_TABLE[v & 0xF];

        return new String(hex);
    }


    /**
     *parses a hexadecimal string and returns it as a long.
     * @param hexString
     * @return
     * @throws NumberFormatException
     */
    public static long toLong(String hexString) throws NumberFormatException{
        long answer=0;
        StringBuffer strbuf = new StringBuffer();

        for (int i=0; i<hexString.length(); i++){
            char x = hexString.charAt(i);
            if ((x!=':')&&(x!=' ')&&(x!='-')){
                strbuf.append(x);
            }
        }
        String concatString = new String(strbuf);
        int len = concatString.length();
        for (int i=0; i<len; i++){
            int d=0;
            char x = concatString.charAt(len-(i+1));
            if (x=='0'){d=0;}
            else if (x=='1'){d=1;}
            else if (x=='2'){d=2;}
            else if (x=='3'){d=3;}
            else if (x=='4'){d=4;}
            else if (x=='5'){d=5;}
            else if (x=='6'){d=6;}
            else if (x=='7'){d=7;}
            else if (x=='8'){d=8;}
            else if (x=='9'){d=9;}
            else if ((x=='a')|(x=='A')){d=10;}
            else if ((x=='b')|(x=='B')){d=11;}
            else if ((x=='c')|(x=='C')){d=12;}
            else if ((x=='d')|(x=='D')){d=13;}
            else if ((x=='e')|(x=='E')){d=14;}
            else if ((x=='f')|(x=='F')){d=15;}

            else {
                throw new NumberFormatException(x+ " is not a recognised hex digit");
            }
            long col=1;
            for (int j=0; j<i; j++){
                col=col*16;
            }
            answer=answer+(col*d);

            //Log.d(TAG,5, "Kidney in: "+hexString+", out: "+Long.toHexString(answer));
        }
        return answer;
    }
    /**
     * returns a long as a byte array.
     * @param l
     * @return
     */
    public static byte[] longToByteArray(long l) {
        byte[] bArray = new byte[8];
        ByteBuffer bBuffer = ByteBuffer.wrap(bArray);
        LongBuffer lBuffer = bBuffer.asLongBuffer();
        lBuffer.put(0, l);
        return bArray;
    }

    /**
     * Returns a reasonably random long. As secure as the underlying implementation of SecureRandom, probably.
     * @return
     */
    public static long randomLong(){
        byte[] arr= new byte[8];
        RANDOM.nextBytes(arr);
        int i = 0;
        int len = 8;
        int cnt = 0;
        byte[] tmp = new byte[len];
        for (i = 0; i < len; i++) {
            tmp[cnt] = arr[i];
            cnt++;
        }
        long accum = 0;
        i = 0;
        for ( int shiftBy = 0; shiftBy < 32; shiftBy += 8 ) {
            accum |= ( (long)( tmp[i] & 0xff ) ) << shiftBy;
            i++;
        }
        return accum;
    }
}