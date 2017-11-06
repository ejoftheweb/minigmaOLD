package uk.co.platosys.tapp.node.models;

public class Role {
    private String roleName;

    private static Role AUTHOR_ROLE= new Role("author");
    private static Role PUBLISHER_ROLE=new Role("publisher");
    private static Role REFEREE_ROLE=new Role("referee");
    private static Role ENDORSER_ROLE=new Role("endorser");
    private static Role AGREEMENT_ROLE=new Role("agreement");
    private static Role SERVER_ROLE=new Role("server");
    private Role(String roleName){
        this.roleName=roleName;
    }
    public String getRoleName(){
        return this.roleName;
    }
   /* public static Role getRole(String roleName){
        return new Role(roleName);
    }*/
}
