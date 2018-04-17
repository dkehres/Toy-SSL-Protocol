/**
* <CBC> This class (Cipher Block Chaining) is used with a block map to encrypt/decrypt a message
* It can take text, run it through a chaining block cipher, and reverse that process
*
* @author Joe Mesnard
* @date March 1, 2018
*/
package cipher;

public class CBC {
    
    int[] blockMap;
    
        public CBC(int[] map) {
        this.blockMap = map;
        }
        
        public String encrypt(String inputText, byte initC) {
        
        String outputText = "";
        int testInt;
        byte cValue = (byte)initC;
        byte testByte, mostSigNibble, leastSigNibble;
        
        for (int i = 0; i < inputText.length(); i++) {

            //Get character as byte
            testByte = (byte)inputText.charAt(i);
            
            //Get first four bits
            mostSigNibble = (byte)((testByte >> 4) & 0b00001111);
            mostSigNibble = (byte) (cValue ^ mostSigNibble);
            mostSigNibble = (byte) this.blockMap[mostSigNibble];
            cValue = mostSigNibble; 
            
            //Get second four bits
            leastSigNibble = (byte) (testByte & (byte) 0b00001111);
            leastSigNibble = (byte) (cValue ^ leastSigNibble);
            leastSigNibble = (byte) this.blockMap[leastSigNibble];
            cValue = leastSigNibble;
            
            //Put both encrypted nibbles together
            testInt = (int)(mostSigNibble << 4) + leastSigNibble;
            
            //Cast the encrypted byte to a character
            outputText += (char) testInt;
        }
        return outputText;
    }   
        
 
    public String decrypt(String inputText, byte initC) {
        
        String outputText = "";
        int testInt;
        byte cValue = (byte)initC;
        byte beforeMapTemp;
        byte testByte, mostSigNibble, leastSigNibble;
        
        for (int i = 0; i < inputText.length(); i++) {

            //Get character as byte
            testByte = (byte)inputText.charAt(i);
            
            //Get first four bits
            mostSigNibble = (byte)((testByte >> 4) & 0b00001111);
            beforeMapTemp = mostSigNibble;
            mostSigNibble = (byte) this.blockMap[mostSigNibble];
            mostSigNibble = (byte) (cValue ^ mostSigNibble);
            cValue = beforeMapTemp;
    
            //Get second four bits
            leastSigNibble = (byte) (testByte & (byte) 0b00001111);
            beforeMapTemp = leastSigNibble;
            leastSigNibble = (byte) this.blockMap[leastSigNibble];
            leastSigNibble = (byte) (cValue ^ leastSigNibble);
            cValue = beforeMapTemp;
            
            //Put both encrypted nibbles together
            testInt = (int)(mostSigNibble << 4) + leastSigNibble;
            
            //Cast the encrypted byte to a character
            outputText += (char) testInt;
        }
        return outputText;
    }  
            
            
    public void reverseMap(){
        int[] tempMap = new int[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};   
        
        // Switch map
        for (int i = 0; i < 16; i++) { tempMap[this.blockMap[i]] = i; }
        
        //Copy new map to block map
        System.arraycopy(tempMap, 0, this.blockMap, 0, 16);
    }
        
    public static void testCipherBlockChaining(){
        String inputText = "Hello! This is Cipher Block Chaining!";
        String encryptedText, decryptedText;
        byte initC = 0b00000001;
        
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
        
        System.out.println("\n********CIPHER BLOCK CHAINING TESTS********");
        CBC blockCipherTest = new CBC(testmap);
        System.out.println("Input text: " + inputText);
        encryptedText = blockCipherTest.encrypt(inputText, initC);
        System.out.println("Encrypted Text: " + encryptedText);
        blockCipherTest.reverseMap();
        decryptedText = blockCipherTest.decrypt(encryptedText, initC);
        System.out.println("Decrypted Text: " + decryptedText);
        System.out.println("********END CIPHER BLOCK CHAINING TESTS********\n");
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
    



