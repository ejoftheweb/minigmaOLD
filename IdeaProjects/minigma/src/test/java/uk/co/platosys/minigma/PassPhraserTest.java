package uk.co.platosys.minigma;

import org.junit.Test;

public class PassPhraserTest {
    @Test
    public void getPassPhraseTest(){
        PassPhraser passPhraser = new PassPhraser();
        System.out.println(passPhraser.getPassPhrase(6));


    }
}
