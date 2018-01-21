package uk.co.platosys.minigma;

import uk.co.platosys.minigma.exceptions.MinigmaException;

import java.util.Iterator;

/**
 * This interface defines how Locks are stored. Minigma provides one implementation, MinigmaLockStore,
 * which uses PGPPublicKeyRings as a storage mechanism.
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

    boolean removeLock(long lockID);

    Lock getLock(long keyID);

    Iterator<Lock> iterator() throws MinigmaException;

    Lock getLock(String userID)throws MinigmaException;

    boolean contains(String userID);

    long getStoreId();

    String getUserID(long keyID);

    int getCount();//returns the number of keys held by  this Lockstore
}
