package uk.co.platosys.minigma;

import org.bouncycastle.openpgp.PGPSignature;

public final class Certificate extends BaseSignature {
    public Certificate(PGPSignature pgpSignature){
        super (pgpSignature);

    }
    public boolean isRevocation(){
        return this.type==PGPSignature.KEY_REVOCATION;
    }
}
