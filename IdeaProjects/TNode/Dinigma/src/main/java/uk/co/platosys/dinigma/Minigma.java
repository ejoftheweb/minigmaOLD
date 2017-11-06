/*
 * Created 9 Dec 2016
 * www.platosys.co.uk 
 */
package uk.co.platosys.dinigma;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import org.spongycastle.bcpg.CompressionAlgorithmTags;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import uk.co.platosys.dinigma.engines.CryptoEngine;
import uk.co.platosys.dinigma.exceptions.MinigmaException;
import uk.co.platosys.dinigma.exceptions.SignatureException;
import uk.co.platosys.dinigma.exceptions.UnsupportedAlgorithmException;
import uk.co.platosys.dinigma.utils.MinigmaUtils;

/**
 * @author edward

 */
public class Minigma {
	public static String TAG = "Minigma";
       public  static final String PROVIDER_NAME = "SC";
       public static final int  HASH_ALGORITHM = HashAlgorithmTags.SHA512;
       public  static final int  COMPRESS_ALGORITHM = CompressionAlgorithmTags.UNCOMPRESSED;
        public static final int  STRONG_ALGORITHM = SymmetricKeyAlgorithmTags.AES_256;
        public static final int WEAK_ALGORITHM=SymmetricKeyAlgorithmTags.TRIPLE_DES;
        public static final Provider PROVIDER = initialiseProvider();
        public static final String LOCK_DIRNAME="lock";
        public static final String KEY_DIRNAME="key";
       public static final  String [] BIOMES =new String[] { "aardvark", "absurd", "accrue", "acme", "adrift",
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
        /**
         * This takes an String and encrypts it with the given Lock
         * @param lock - the Lock with which to encrypt it;
         * @return
         * @throws MinigmaException 
         */
        public static String lock(String clearString, Lock lock) throws MinigmaException{
          byte[] literalData=MinigmaUtils.toByteArray(clearString);
          byte[] compressedData = MinigmaUtils.compress(literalData);
          byte[] encryptedData=CryptoEngine.encrypt(compressedData, lock);
          return MinigmaUtils.encode(encryptedData);
          
        }
            
	 /** This takes an EncryptedData String and returns  the cleartext
	 * @return
	 * @throws Exception 
	 */
	 public static String unlock(String ciphertext, Key key, char[] passphrase) throws Exception {
	  byte[] bytes = MinigmaUtils.decode(ciphertext);
	  ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
	   return CryptoEngine.decrypt(bais, key, passphrase);
	}
 /**
  * Returns a Base64-encoded String which is the signature of the passed-in String argument
  * signed with the passed-in Key.
  * @return
 * @throws MinigmaException 
  */
  public static String sign(String string, Key key, char[] passphrase ) throws MinigmaException{
	 return key.sign(string, passphrase);
  }
  
  public static long verify(String signedMaterial, String signature, LockStore lockStore)throws MinigmaException, UnsupportedAlgorithmException, SignatureException {
  	   Iterator<Lock> lockit = lockStore.iterator();
       while(lockit.hasNext()){
	       Lock lock = lockit.next();
	       if (lock.verify(signedMaterial, signature)){
	        	  return lock.getLockID();
	       }
       }
       return 0l;
  }

   
 
 //Private methods

 

 static Provider initialiseProvider(){
    Provider provider = new BouncyCastleProvider();
    Security.addProvider(provider);
    return provider;
}



}

