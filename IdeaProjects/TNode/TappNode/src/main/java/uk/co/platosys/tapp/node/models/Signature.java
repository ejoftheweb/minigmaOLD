package uk.co.platosys.tapp.node.models;

/**
 * The Signature class is essentially just a convenient bean wrapper.
 * Note that the only actual signing done on the server is when the server itself signs the Tapp on first
 * submission.
 * @author edward
 *
 */
public class Signature {

    private Role role;
    private String value;
    private String method;
    private String tappsterID;

    public Signature() {
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getRolename() {
        return role.getRoleName();
    }

    public String getTappsterID() {
        return tappsterID;
    }

    public void setTappsterID(String tappsterID) {
        this.tappsterID = tappsterID;
    }
}