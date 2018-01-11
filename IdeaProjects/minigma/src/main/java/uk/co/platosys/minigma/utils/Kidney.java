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
    public static final  String [] EVEN_BIOMES =new String[] {
            "aardvark", "absurd", "accrue", "acme", "adrift",
            "adult", "afflict", "ahead", "aimless", "Algol",
            "allow", "alone", "ammo", "ancient", "apple",
            "artist", "assume", "Athens", "atlas", "Aztec",
            "baboon", "backfield", "backward", "banjo", "beaming",
            "bedlamp", "beehive", "beeswax", "befriend", "Belfast",
            "berserk", "billiard", "bison", "blackjack", "blockade",
            "blowtorch", "bluebird", "bombast", "bookshelf", "brackish",
            "breadline", "breakup", "brickyard", "briefcase", "Burbank",
            "button", "buzzard", "cement", "chairlift", "chatter",
            "checkup", "chisel", "choking", "chopper", "Christmas",
            "clamshell", "classic", "classroom", "cleanup", "clockwork",
            "cobra", "commence", "concert", "cowbell", "crackdown",
            "cranky", "crowfoot", "crucial", "crumpled", "crusade",
            "cubic", "dashboard", "deadbolt", "deckhand", "dogsled",
            "dragnet", "drainage", "dreadful", "drifter", "dropper",
            "drumbeat", "drunken", "Dupont", "dwelling", "eating",
            "edict", "egghead", "eightball", "endorse", "endow",
            "enlist", "erase", "escape", "exceed", "eyeglass",
            "eyetooth", "facial", "fallout", "flagpole", "flatfoot",
            "flytrap", "fracture", "framework", "freedom", "frighten",
            "gazelle", "Geiger", "glitter", "glucose", "goggles",
            "goldfish", "gremlin", "guidance", "hamlet", "highchair",
            "hockey", "indoors", "indulge", "inverse", "involve",
            "island", "jawbone", "keyboard", "kickoff", "kiwi",
            "klaxon", "locale", "lockup", "merit", "minnow",
            "miser", "Mohawk", "mural", "music", "necklace",
            "Neptune", "newborn", "nightbird", "Oakland", "obtuse",
            "offload", "optic", "orca", "payday", "peachy",
            "pheasant", "physique", "playhouse", "Pluto", "preclude",
            "prefer", "preshrunk", "printer", "prowler", "pupil",
            "puppy", "python", "quadrant", "quiver", "quota",
            "ragtime", "ratchet", "rebirth", "reform", "regain",
            "reindeer", "rematch", "repay", "retouch", "revenge",
            "reward", "rhythm", "ribcage", "ringbolt", "robust",
            "rocker", "ruffled", "sailboat", "sawdust", "scallion",
            "scenic", "scorecard", "Scotland", "seabird", "select",
            "sentence", "shadow", "shamrock", "showgirl", "skullcap",
            "skydive", "slingshot", "slowdown", "snapline", "snapshot",
            "snowcap", "snowslide", "solo", "southward", "soybean",
            "spaniel", "spearhead", "spellbind", "spheroid", "spigot",
            "spindle", "spyglass", "stagehand", "stagnate", "stairway",
            "standard", "stapler", "steamship", "sterling", "stockman",
            "stopwatch", "stormy", "sugar", "surmount", "suspense",
            "sweatband", "swelter", "tactics", "talon", "tapeworm",
            "tempest", "tiger", "tissue", "tonic", "topmost",
            "tracker", "transit", "trauma", "treadmill", "Trojan",
            "trouble", "tumor", "tunnel", "tycoon", "uncut",
            "unearth", "unwind", "uproot", "upset", "upshot",
            "vapor", "village", "virus", "Vulcan", "waffle",
            "wallet", "watchword", "wayside", "willow", "woodlark",
            "Zulu"};
    public static final String[] ODD_BIOMES= new String[] {
            "adroitness","adviser", "aftermath","aggregate","alkali",
            "almighty","amulet","amusement","antenna","accident",
            "Apollo","armistice", "article","asteroid","Atlantic",
            "atmosphere","autopsy","babylon","backwater","barbecue",
            "belowground","bifocals","bodyguard","bookseller","borderline",
            "bottomless","Bradbury","bravado","Brazilian","breakaway",
            "Burlington","businessman","butterfat","Camelot","candidate",
            "cannonball","capricorn","caravan","caretaker","celebrate",
            "cellulose","certify","chambermaid","Cherokee","Chicago",
            "clergyman","coherence","combustion","commando","company",
            "component","concurrent","confidence","conformist","congregate",
            "consensus","consulting","corporate","corrosion","councilman",
            "crossover","crucifix","cumbersome","customer","Dakota",
            "decadence","December","decimal","designing","detector",
            "detergent","determine","dicator","dinosaur","direction",
            "disable","disbelief","disruptive","distortion","document",
            "embezzle","enchanting","enrolment","enterprise","equation",
            "equipment","escapade","Eskimo","everyday","examine",
            "existence","exodus","fascinate","filament","finicky",
            "forever","fortitude","frequency","gadetry","Galveston",
            "getaway","glossary","gossamer","graduate","gravity",
            "guitarist","hamburger","Hamilton","handiwork","hazardous",
            "headwaters","hemisphere","hesitate","hideaway","holiness",
            "hurricane","hydraulic","impartial","impetus","inception",
            "indigo","inertia","infancy","inferno","informant",
            "insincere","insurgent","integrate","intention","inventive",
            "Istanbul","Jamaica","Jupiter","leprosy","letterhead",
            "liberty","maritime","matchmaker","maverick","Medusa",
            "megaton","microscope","microwave","midsummer","millionaire",
            "miracle","misnomer","molasses","molecule","Montana",
            "monument","mosquito","narrative","nebula","newsletter",
            "Norwegian","October","Ohio","onlooker","opulent",
            "Orlando","outfielder","Pacific","pandemic","Pandora",
            "paperweight","paragon","paragraph","paramount","passenger",
            "pedigree","pegasus","penetrate","perceptive","performance",
            "pharmacy","phonetic","photograph","pioneer","pocketful",
            "politeness","positive","potato","processor","provincial",
            "proximate","puberty","publiser","pyramid","quantity",
            "racketeer","rebellion","recipe","recover","repellent",
            "replica","reproduce","resistor","responsive","retraction",
            "retrieval","retrospect","revenue","revival","revolver",
            "sandalwood","sardonic","Saturday","savagery","scavenger",
            "sensation","sociable","souvenir","specialist","speculate",
            "stethoscope","stupendous","supportive","surrender","suspicious",
            "sympathy","tambourine","telephone","therapist","tobacco",
            "tolerance","tomorrow","torpedo","tradition","travesty",
            "trombonist","truncated","typewriter","ultimate","undaunted",
            "underfoot","unicorn","unify","universe","unravel",
            "upcoming","vacancy","vagabond","vertigo","Virginia",
            "visitor","vocalist","voyager","warranty","Waterloo",
            "whimsical","Wichita","Wilmington","Wyoming","yesteryear",
            "Yucatan"};




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
     * This returns a list of English words as long as the fingerprint (currently 20 bytes).
     * They are selected from the PGP word list.
     *
     * @param fingerprint
     * @return
     */
    public static List<String> getFingerprint(byte[] fingerprint) {
        ArrayList<String> arrayList= new ArrayList<>();
        boolean even = true;
       for (byte sbyte:fingerprint){
           int fbyte=sbyte;
           if(fbyte<0){fbyte=fbyte+256;}
           //System.out.println(fbyte+" "+String.format("%x", fbyte));
            if (even) {
                //System.out.println(EVEN_BIOMES[fbyte]);
                arrayList.add(EVEN_BIOMES[fbyte]);
                even=false;
            }else{
                //System.out.println(ODD_BIOMES[fbyte]);

                arrayList.add(ODD_BIOMES[fbyte]);
                even=true;
            }
        }

        return arrayList;


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