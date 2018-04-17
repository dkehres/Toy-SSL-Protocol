/**
* <SubstitutionCipher> This class is used to create and test a substitution 
* cipher. It used a default cipher or takes a cipher from the user to encrypt a
* message from the user.
*
* @author Joe Woodruff
* @date March 1, 2018
*/

package cipher;

import java.math.BigInteger;
import java.io.*;
import java.security.SecureRandom;


public class SubstitutionCipher {
  
    // Create Variable
    String cipherText;

    // Default Constructor
    public SubstitutionCipher()
    {
        cipherText = new String("9876543210");
    }
    
    // Overload Constructor
    public SubstitutionCipher(String cipher)
    {
        cipherText = cipher;
    }
    
    
    public BigInteger SubstitutionCipherEncrypt(BigInteger inputText)
    {
        // Initializes, sets and creates variables
        BigInteger input = inputText;
        String cipher = this.cipherText;
        String temp = "";
        BigInteger returnText; 
        String inputString = input.toString();
        
       // Encrypts the message
        for (int i = 0; i < inputString.length(); i++)
        {
            int x = Character.getNumericValue(inputString.charAt(i));
            temp += cipher.charAt(x);
        }
        
        // Returns the message
        returnText = new BigInteger(temp);
        return returnText;
    }
    
    public BigInteger SubstitutionCipherDecrypt(BigInteger encryptedText)
    {
        // Initializes, sets and creates variables
        BigInteger input = encryptedText;
        String cipher = this.cipherText;
        String decryptionCipher;
        String temp = "";
        BigInteger returnText = new BigInteger("0");
        String inputString = input.toString();
        
        // Used as an array to create the decryption cipher
        decryptionCipher = "abcdefghij";
        

        // Creates the decyption cipher
        for(int i = 0; i < decryptionCipher.length(); i++)
        {
            int index = Character.getNumericValue(cipher.charAt(i));
            char x = decryptionCipher.charAt(index);
            String y = "";
            y += i;
            char z = y.charAt(0);
            decryptionCipher = decryptionCipher.replace(x, z);
        }
  
        // Decrypts the message
        for (int i = 0; i < inputString.length(); i++)
        {
            int x = Character.getNumericValue(inputString.charAt(i));
            temp += decryptionCipher.charAt(x);
        }
        
        // Returns the decrypted message
        returnText = new BigInteger(temp);
        return returnText;
    }
    
    
    
    public static void TestSubstitution()
    {
        // Runs test 1 with the default constructor
        BigInteger inputTextTest1 = new BigInteger("12345678901234567890");
        SubstitutionCipher test1 = new SubstitutionCipher();
        BigInteger encryptedTextTest1 = test1.SubstitutionCipherEncrypt(inputTextTest1);
        BigInteger decryptedTextTest1 = test1.SubstitutionCipherDecrypt(encryptedTextTest1);
        
        //Runs test 2 with the overload constructor
        BigInteger inputTextTest2 = new BigInteger("12345678901234567890");
        SubstitutionCipher test2 = new SubstitutionCipher("5647382910");
        BigInteger encryptedTextTest2 = test2.SubstitutionCipherEncrypt(inputTextTest2);
        BigInteger decryptedTextTest2 = test2.SubstitutionCipherDecrypt(encryptedTextTest2);
        
        System.out.println("********Substitution TESTS********");
        
        // Output for test 1
        System.out.println("Test1: \ninput: \"" + inputTextTest1 + "\" Using the default cipher:");
        System.out.println("Test1 Encrypted Text:");
        System.out.println(encryptedTextTest1);
        System.out.println("Test1 Decrypted Text:");
        System.out.println(decryptedTextTest1);
        
        // Output for test 2
        System.out.println("Test2: \ninput: \"" + inputTextTest2 + "\" Using the default cipher:");
        System.out.println("Test2 Encrypted Text:");
        System.out.println(encryptedTextTest2);
        System.out.println("Test2 Decrypted Text:");
        System.out.println(decryptedTextTest2);
        
        System.out.println("********END Substitution TESTS********");
    }
}