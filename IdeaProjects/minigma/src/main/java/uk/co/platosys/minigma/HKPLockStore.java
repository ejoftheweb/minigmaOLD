package uk.co.platosys.minigma;

import uk.co.platosys.minigma.exceptions.MinigmaException;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Iterator;

/**This is an implementation of LockStore that uses public keyservers
 * as the backing store, with which it communicates using the HKP protocol
 * based on http.
 *
 */

public class HKPLockStore implements LockStore {
    private URL url;

    public HKPLockStore(URL url){
        this.url=url;
    }


    @Override
    public boolean addLock(Lock lock) {
        try {
            HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
            httpURLConnection.setRequestMethod("POST");
            return false;
        }catch(Exception x){
            return false;
        }
    }

    /** This method always returns false. It is not practicable (or for that matter usually ever desirable) to remove a public key from
     * a public keyserver.
     * @param lockID
     * @return always false*/
    @Override
    public boolean removeLock(byte[] lockID) {
        return false;
    }

    @Override
    public Lock getLock(byte[] keyID) {
        return null;
    }

    @Override
    public Iterator<Lock> iterator() throws MinigmaException {
        return null;
    }

    @Override
    public Lock getLock(String userID) throws MinigmaException {
        return null;
    }

    @Override
    public boolean contains(String userID) {
        return false;
    }

    @Override
    public long getStoreId() {
        return 0;
    }

    @Override
    public String getUserID(byte[] keyID) {
        return null;
    }

    @Override
    public String getUserID(long keyID) {
        return null;
    }

    @Override
    public int getCount() {
        return 0;
    }
}
