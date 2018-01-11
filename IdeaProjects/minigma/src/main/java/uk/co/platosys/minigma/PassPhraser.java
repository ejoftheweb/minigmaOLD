package uk.co.platosys.minigma;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class PassPhraser {
    /**
     *  in the Minigma library, a Key is unlocked with a Passphrase, which is a char array.
     *
     *  Random passphrases are known to be more secure than human-generated ones which are
     *
     *
     *  Passphraser generates passphrases from the EFF alternative short-list which is 6^4 words
     *  long.
     *
     *
     *
     */
    private  File wordListFile;
    private List<String> wordList;
public  int WORDLIST_SIZE=1297;
public static final String WORDSEPARATOR = " ";

public PassPhraser(){
    //System.out.println("running constructor");
    this.wordListFile=new File("/home/edward/platosys/minigma/resources/wordlist");
    this.wordList=loadWordList();
}
    public char[] getPassPhrase(int words) {
        SecureRandom secureRandom = new SecureRandom();
        StringBuffer buffer= new StringBuffer();
        for (int i = 0; i < words; i++) {
            try {
                int word = secureRandom.nextInt(WORDLIST_SIZE);
                if (i > 0) {
                    buffer.append(WORDSEPARATOR);
                }
                buffer.append(wordList.get(word));
            }catch (Exception x) {
                //probably an array out of bounds one
            }
        }
        return buffer.toString().toCharArray();
    }

    private  List<String> loadWordList() {
        List<String> wordList=new ArrayList<>();
        try {
            BufferedReader bufferedReader = new BufferedReader( new FileReader(wordListFile));
            String line;
            while ((line=bufferedReader.readLine())!=null){
                //System.out.println((line));
                String word = line.split("\t")[1];
                wordList.add(word);
                //System.out.println(word);
            }


        }catch(Exception x){
            System.out.println(x.getClass()+"\n"+x.getMessage());
        }
        return wordList;
    }
}
