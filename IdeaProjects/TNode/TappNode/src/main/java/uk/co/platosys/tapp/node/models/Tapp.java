package uk.co.platosys.tapp.node.models;

import com.google.cloud.datastore.Entity;
import org.jdom2.Document;

/**Tapp is the java instantiation of a Tapp
 *
 * The purpose of a Node is securely to store and to retrieve Tapps, passed to it by client apps.
 * A Tapp is always transported as XML and in this implementation of the TappNode interface, it uses
 * Google NoSQL Datastore to retrieve and store the material.
 *
 */
public class Tapp {
    private Entity entity;
    private Document document;
    public Tapp (Entity entity){
        this.entity=entity;
        this.document=new Document();
    }
    public Tapp (Document document){
        this.document=document;
        //this.entity=//
    }
}
