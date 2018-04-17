/**
* <ShiftCipher> This class is used with a shift value to encrypt/decrypt a message
* It can take text, run it through a shift cipher, and reverse that process
*
* @author Joe Mesnard
* @date March 1, 2018
*/
package cipher;

public class ShiftCipher {
    
    public String shift(String inputText, int shiftValue) {
        
        String outputText = "";
        
        for (int i = 0; i < inputText.length(); i++) {
            int test = (int)inputText.charAt(i) + shiftValue;
            char testChar = (char)test;
            outputText += testChar;
        }
        return outputText;
    }
    
    public String unshift(String inputText, int shiftValue) {
        return shift(inputText, -shiftValue);
    }
    
}
