package uk.co.platosys.minigma;


import org.bouncycastle.bcpg.sig.NotationData;

/**A helper class for handling OpenPGP NotationData as defined in RFC 2440. Notations are
 * essentially name-value pairs that can be attached to pgp signatures.
 *
 * The class does almost exactly the same as org.bouncycastle.bcpg.sig.NotationData - it holds
 * the two string fields and flags for critical and human-readable.
 */
public class Notation {
    private boolean isCritical=false;
    private boolean isHumanReadable=false;
    private String name;
    private String value;

    public Notation (String name, String value){
        this.name=name;
        this.value=value;
    }
    public NotationData notationData(){
        return new NotationData(isCritical, isHumanReadable, name, value);
    }

    public boolean isCritical() {
        return isCritical;
    }

    public void setCritical(boolean critical) {
        isCritical = critical;
    }

    public boolean isHumanReadable() {
        return isHumanReadable;
    }

    public void setHumanReadable(boolean humanReadable) {
        isHumanReadable = humanReadable;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
