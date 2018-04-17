/**
*
* <p>Polyalphabetic Cipher (Polyalphabetic Cipher) Applies (or reverses) shift to each character of input based on shifts array
* 
* 
* @author Jacob
* @date 3/1/2018
*/

package cipher;

public class PolyalphabeticCipher {
    // each element is the distance to shift each character
    int[] shifts;
    
    public PolyalphabeticCipher(int[] shifts) {
        this.shifts = shifts;
    }
    
    public String encrypt(String inputText) {
        return applyShift(inputText, true);
    }
    
    public String decrypt(String inputText) {
        return applyShift(inputText, false);
    }
    
    private String applyShift(String inputText, Boolean encrypt) {
        String outputText = "";
        ShiftCipher shiftCipher = new ShiftCipher();
        
        for (int i = 0; i < inputText.length(); i++) {
            String aLetter = Character.toString(inputText.charAt(i));
            //wrap through shift array if you get to the end of it
            int shiftValue = shifts[i % shifts.length];
            //uses relevant shift cipher option
            if (encrypt) {
               outputText += shiftCipher.shift(aLetter, shiftValue);
            } else {
               outputText += shiftCipher.unshift(aLetter, shiftValue); 
            }
        }
        return outputText;
    }
    
    public static void testPolyalphabetic() {
        //POLYALPHABETIC TESTING
        String inputTextPolyalph = "hello";
        int[] shifts = {1, 2, 3};
        String encryptedText;
        String decryptedText;
        PolyalphabeticCipher polyalphabeticTest = new PolyalphabeticCipher(shifts);
        System.out.println("\n********POLYALPHABETIC TESTS********");
        System.out.println("Input Text: "+inputTextPolyalph);
        encryptedText = polyalphabeticTest.encrypt(inputTextPolyalph);
        System.out.println("Encrypted Text: "+encryptedText);
        decryptedText = polyalphabeticTest.decrypt(encryptedText);
        System.out.println("Decrypted Text: "+decryptedText);
        System.out.println("********END POLYALPHABETIC TESTS********\n");
    }
    
}
