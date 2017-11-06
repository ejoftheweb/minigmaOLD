package uk.co.platosys.tapp.node.models;

public class Tappster {
    /**
     * Created by edward on 08/12/16.
     */
    import uk.co.platosys.dinigma.Lock;


    public class Tappster {
        private String username;
        private String id;
        private Lock lock;

        public Tappster (){}

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public Lock getLock() {
            return lock;
        }

        public void setLock(Lock lock) {
            this.lock = lock;
        }
}
