/**
* <DigitalSignature> This class is used to create and test a Digital Signature.
* It uses a hash function and private key to sign a message for the user.
*
* @author Joe Woodruff
* @date March 1, 2018
*/
package cipher;

import java.math.BigInteger;
import java.io.*;
import java.security.SecureRandom;

public class DigitalSignature {
    
    // Creates Variables
    static BigInteger message;
    static BigInteger encryptedMessage;
    static RSAKey privateKey;
    static RSAKey publicKey;
    static BigInteger hash; 
    
    
 
    public static BigInteger DigitalSignatureEncrypt(BigInteger userMessage, BigInteger userHash, RSAKey userPrivateKey)
    {
        //Sets Variables
        message = userMessage;
        hash = userHash;
        privateKey = userPrivateKey;
        
        // This signs the message
        encryptedMessage = hash(message, hash);
        encryptedMessage = RSA.rsaEncrypt(encryptedMessage, privateKey);
        return encryptedMessage;
    }
    
    
    public static boolean DigitalSignatureVerification(BigInteger userMessage, BigInteger userEncryptedMessage, BigInteger userHash, RSAKey userPublicKey)
    {
        //Sets Variables
        message = userMessage;
        hash = userHash;
        publicKey = userPublicKey;
        
        //Hashes the original message
        BigInteger hashedMessage = hash(message, hash);
        
        //Decrypts the encrypted message
        encryptedMessage = userEncryptedMessage;
        BigInteger decryptedMessage = RSA.rsaDecrypt(encryptedMessage, publicKey);
        
        //Compares the two hashed methods
        if (!hashedMessage.equals(decryptedMessage))
        {
            return false;
        }
        return true;
    }
    
    // This message mods a big integer by the hash value
    public static BigInteger hash(BigInteger userMessage, BigInteger userHash)
    {
        message = userMessage;
        BigInteger hashedMessage = message.mod(userHash);
        return hashedMessage;
    }
    
    public static void TestDigitalSignature()
    {
        // Test 1 Should return true
        RSA RSATest1 = new RSA();
        BigInteger messageTest1 = new BigInteger("12345678900987654321");
        BigInteger hashTest1 = new BigInteger("13");
        BigInteger signedMessageTest1 = DigitalSignatureEncrypt(messageTest1, hashTest1, RSATest1.getPrivateKey());
        boolean verificationTest1 = DigitalSignatureVerification(messageTest1, signedMessageTest1, hashTest1, RSATest1.getPublicKey());
        
        //Test 2 Should return true
        RSA RSATest2 = new RSA();
        BigInteger messageTest2 = new BigInteger("9876543210");
        BigInteger hashTest2 = new BigInteger("13");
        BigInteger signedMessageTest2 = DigitalSignatureEncrypt(messageTest2, hashTest2, RSATest2.getPrivateKey());
        boolean verificationTest2 = DigitalSignatureVerification(messageTest2, signedMessageTest2, hashTest1, RSATest2.getPublicKey());
        
        //Test 3 Should return false
        BigInteger messageTest3 = new BigInteger("1234567890");
        BigInteger hashTest3 = new BigInteger("13");
        BigInteger signedMessageTest3 = DigitalSignatureEncrypt(messageTest3, hashTest3, RSATest1.getPrivateKey());
        boolean verificationTest3 = DigitalSignatureVerification(messageTest3, signedMessageTest3, hashTest3, RSATest2.getPublicKey());
        
        System.out.println("********Digital Signature TESTS********");
        
        //Test 1 output
        System.out.println("Test1: \nmessage: \"" + messageTest1 + "\" Using the default cipher:");
        System.out.println("Test1 Encrypted Text:");
        System.out.println(signedMessageTest1);
        System.out.println("Test1 Verification that the Message Matches:");
        System.out.println("The message came from the correct sender. "+ verificationTest1 + "\n");
        
        //Test 2 output
        System.out.println("Test2: \nmessage: \"" + messageTest2 + "\" Using the default cipher:");
        System.out.println("Test2 Encrypted Text:");
        System.out.println(signedMessageTest2);
        System.out.println("Test2 Verification that the Message Matches:");
        System.out.println("The message came from the correct sender. "+ verificationTest2 + "\n");
        
        //Test 3 output
        System.out.println("Test3: \nmessage: \"" + messageTest3 + "\" Using the default cipher:");
        System.out.println("Test3 Encrypted Text:");
        System.out.println(signedMessageTest3);
        System.out.println("Test3 Verification that the Message Matches:");
        System.out.println("The message came from the correct sender. "+ verificationTest3 + "\n");

        System.out.println("********END Digital Signature TESTS********");
    }
}
