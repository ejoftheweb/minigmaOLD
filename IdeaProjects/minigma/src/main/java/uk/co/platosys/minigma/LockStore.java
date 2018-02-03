package uk.co.platosys.minigma;

import uk.co.platosys.minigma.exceptions.MinigmaException;

import java.util.Iterator;

/**
 * This interface defines how Locks are stored. Minigma provides one implementation, MinigmaLockStore,
 * which uses PGPPublicKeyRings as a storage mechanism.
 *
 * Minigma does not use OpenPGP KeyIDs, but only fingerprints (the 160-bit timestamped hash of the public key)
 * OpenPGP short (32-bit) KeyIDs are broadly deprecated as it is now trivial to generate collisions, that is,
 * keys that have the same short keyID. Long (64-bit) keyIDs are much more secure, but collisions are theoretically
 * possible. Using the 160-bit fingerprint is less convenient if this is ever to be done humanly but Minigma is all about
 * doing this by machine.
 *
 */
public interface LockStore {
    /**
     * Adds a Lock to a Lockstore. If the Lockstore already contains a Lock with that id, it
     * is replaced (typically because the Lock's certification has changed).
     *
     * @param lock
     * @return
     */
    boolean addLock(Lock lock);

    boolean removeLock(byte[] lockID);

    Lock getLock(byte[] keyID);

    Iterator<Lock> iterator() throws MinigmaException;

    Lock getLock(String userID)throws MinigmaException;

    boolean contains(String userID);

    long getStoreId();

    String getUserID(byte[] keyID);
    String getUserID(long keyID);

    int getCount();//returns the number of keys held by  this Lockstore
}
