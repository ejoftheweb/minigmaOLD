package uk.co.platosys.minigma.utils;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import uk.co.platosys.minigma.Minigma;

import java.io.OutputStream;

public class MinigmaOutputStream extends ArmoredOutputStream {
    public MinigmaOutputStream (OutputStream outputStream){
        super(outputStream);
        setHeader(ArmoredOutputStream.VERSION_HDR, Minigma.VERSION);
        setHeader("Comment:", "Easy OpenPGP library for Java and Android");
    }
}
