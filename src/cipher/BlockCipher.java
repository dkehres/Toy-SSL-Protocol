/**
* <BlockCipher> This class is used with a block map to encrypt/decrypt a message
* It can take text, run it through a block cipher, and reverse that process
*
* @author Joe Mesnard
* @date March 1, 2018
*/
package cipher;

public class BlockCipher {
    
   int[] blockMap;
   
    public BlockCipher(int[] map) {
        this.blockMap = map;
    }

    public String encrypt(String inputText) {
        
        String outputText = "";
        int testInt;
        byte testByte, mostSigNibble, leastSigNibble;
        
        for (int i = 0; i < inputText.length(); i++) {

            //Get character as byte
            testByte = (byte)inputText.charAt(i);
            
            //Encrypt first four bits
            mostSigNibble = (byte)((testByte >> 4) & 0b00001111);
            mostSigNibble = (byte) this.blockMap[mostSigNibble];
            
            //Encrypt second four bits
            leastSigNibble = (byte) (testByte & (byte) 0b00001111);
            leastSigNibble = (byte) this.blockMap[leastSigNibble];
            
            //Put both encrypted nibbles together
            testInt = (int)(mostSigNibble << 4) + leastSigNibble;
            
            //Cast the encrypted byte to a character
            outputText += (char) testInt;
        }
        return outputText;
    }
    
    public String decrypt(String inputText){
        return this.encrypt(inputText);
    }
    
    public void reverseMap(){
        int[] tempMap = new int[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};   
        
        // Switch map
        for (int i = 0; i < 16; i++) { tempMap[this.blockMap[i]] = i; }
        
        //Copy new map to block map
        System.arraycopy(tempMap, 0, this.blockMap, 0, 16);
    }
 
    
    public static void testBlockCipher(){
        String inputText = "Hello! This is a block cipher.";
        String encryptedText, decryptedText;
        
        int[] testmap = new int[]{
            // The above comment is the number the map coresponds to.
            // See the full map below
            // 0000 0001 0010 0011
               15,   9,   4,   8,
            // 0100 0101 0110 0111
               5,   3,   14,  13, 
            // 1000 1001 1010 1011
               10,  2,   6,   0,
            // 1100 1101 1110 1111
               12,  7,   11,  1
        };
        
        System.out.println("\n********BLOCK CIPHER TESTS********");
        BlockCipher blockCipherTest = new BlockCipher(testmap);
        System.out.println("Input text: " + inputText);
        encryptedText = blockCipherTest.encrypt(inputText);
        System.out.println("Encrypted Text: " + encryptedText);
        blockCipherTest.reverseMap();
        decryptedText = blockCipherTest.encrypt(encryptedText);
        System.out.println("Decrypted Text: " + decryptedText);
        System.out.println("********END BLOCK CIPHER TESTS********\n");
    }
    
}

/*
    
    Full Test Map

    Input   Oupput
0    0000    1111   15
1    0001    1001   9
2    0010    0100   4
3    0011    1000   8
4    0100    0101   5
5    0101    0011   3
6    0110    1110   14
7    0111    1101   13
8    1000    1010   10
9    1001    0010   2
10   1010    0110   6
11   1011    0000   0
12   1100    1100   12
13   1101    0111   7
14   1110    1011   11
15   1111    0001   1


*/