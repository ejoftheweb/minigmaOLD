package uk.co.platosys.tapp.node.constants;

import org.jdom2.Namespace;

/**
 * This class contains constants for the element and attribute
 * names in the Tapp xml schema
 * Created by edward on 22/11/16.
 */

public class TappXml {
    //Namespace
    public static final String NSPREFIX="tapp";
    public static final String NSURL="http://tapp.org";
    public static final Namespace NS = Namespace.getNamespace(NSPREFIX, NSURL);

    //attributes
    public static final String ID_ATTNAME="id";
    public static final String NAME_ATTNAME="name";
    public static final String ISAD_ATTNAME="ad";
    public static final String KEY_ATTNAME="key";
    public static final String ROLE_ATTNAME="role";
    public static final String METHOD_ATTNAME="method";
    public static final String VALUE_ATTNAME="value";
    public static final String TAPPSTER_ATTNAME="tappster";
    public static final String DIGEST_ATTNAME="digest";
    public static final String LOCKSTATUS_ATTNAME="lockstatus";
    public static final String ARGS_ATTNAME="args";
    public static final String TIMESTAMP_ATTNAME="timestamp";
    public static final String SRC_ATTNAME="src";
    public static final String SIG_ATTNAME="sig";

    //elements
    public static final String ROOT_ELNAME="tapp";
    public static final String TITLE_ELNAME="title";
    public static final String TWEET_ELNAME="tweet";
    public static final String LOCK_ELNAME="lock";
    public static final String TAPPSTERS_ELNAME="tappsters";
    public static final String TAPPSTER_ELNAME="tappster";
    public static final String SIGNATURES_ELNAME="signatures";
    public static final String SIGNATURE_ELNAME="signature";
    public static final String TAGS_ELNAME="tags";
    public static final String TAG_ELNAME="tag";
    public static final String ADVERT_ELNAME="advert";
    public static final String ABSTRACT_ELNAME="abstract";
    public static final String CONTENT_ELNAME="content";
    public static final String ILLUS_ELNAME="illus";
    public static final String SCRIPTS_ELNAME="scripts";
    public static final String LINKS_ELNAME="links";
    public static final String TEXT_ELNAME="text";
    public static final String MUSCRIPTS_ELNAME="muscripts";
    public static final String NAVLINKS_ELNAME="navlinks";
    public static final String LINK_ELNAME="link";
    public static final String SCRIPT_ELNAME="script";

    //attribute values
    public static final String CLEAR_VAL="clear";//the content element contains cleartext
    public static final String PRIVATE_VAL="private";//the content element contains private cyphertext
    public static final String CYPHER_VAL="cypher";//the content element contains public cyphertext


    //not sure we need these, or they should be values of a type or direction attribute in a
    //<link> element
    public static final String COPY_ELNAME="copy";
    public static final String REPLY_ELNAME="reply";
    public static final String PREV_ELNAME="prev";
    public static final String NEXT_ELNAME="next";
}

