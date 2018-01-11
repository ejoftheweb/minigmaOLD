package uk.co.platosys.minigma;

import uk.co.platosys.minigma.exceptions.MinigmaException;

import java.util.Iterator;

/**
 * This interface defines how Locks are stored. Minigma provides one implementation, MinigmaLockStore,
 * which uses PGPPublicKeyRings as a storage mechanism.
 *
 */
public interface LockStore {
    boolean addLock(Lock lock);

    Lock getLock(long keyID);

    Iterator<Lock> iterator() throws MinigmaException;

    Lock getLock(String userID)throws MinigmaException;

    boolean contains(String userID);

    long getStoreId();

    int getCount();//returns the number of keys held by  this Lockstore
}
