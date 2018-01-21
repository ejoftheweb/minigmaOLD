package uk.co.platosys.minigma;

import org.bouncycastle.openpgp.PGPSignature;

public final class Certificate extends BaseSignature {
    public Certificate(PGPSignature pgpSignature, String signerUserID){
        super (pgpSignature, signerUserID);

    }
}
