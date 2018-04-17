/*
 * This file contains the code used for Message Authentication Code
 * Users are able to pass a message and hash function
 * This will add a secret character and the hashed value 
 * and will check if the message has been altered <p>
 *
 * Message Authentication Code (MAC)
 *
 * @author: Dylan Kehres
 * @date: 3/2/2018
 */
package cipher;

import static cis435proj.asciiConverter.*;
import java.math.BigInteger;
import java.lang.String;
import java.io.*;

public class MAC {
    
    private boolean debugFlag = false;
    
    //Constants used for calculations on BigIntegers
    private static final BigInteger nine = new BigInteger("9");
    private static final BigInteger ten = new BigInteger("10");
    private static final BigInteger oneHundred = new BigInteger("100");
    private static final BigInteger oneThousand = new BigInteger("1000");
    private static final BigInteger ninetynine = new BigInteger("99");
    
    //Class variables used for MAC
    private String sharedSecret;
    private boolean messageStatus;
    
    //Default constructor with predefined secret
    public MAC(){
        sharedSecret = "s";
        messageStatus = false;
    }
    
    //Constructor with user defined secret
    public MAC(String secret){
        sharedSecret = secret;
        messageStatus = false;
    }
    
    public BigInteger send_MAC(String message, BigInteger hashFunc){
        String concatMsg = sharedSecret + message;      //Appends secret to original message
                
        BigInteger numMsg = strToAscii(concatMsg);      //Turns String message into BigInteger ASCII code
        BigInteger hash = numMsg.mod(hashFunc);         //Hash value to append to message
        BigInteger div,messageWithHash;       
        
        messageWithHash = numMsg.multiply(oneThousand).add(hash);       //Appends hashed value to beginning message
        
        if(debugFlag == true){
            System.out.println("SENDING MAC\n");
            System.out.println("Original Message = "+message);
            System.out.println("concatMsg = "+concatMsg);
            System.out.println("numMsg  = "+numMsg);
            System.out.println("Hash = "+hash);
            System.out.println("messageWithHash = "+messageWithHash);
        }
        return messageWithHash;
    }
       
    public String receive_MAC(BigInteger receivedMessage, BigInteger hashFunc){
        BigInteger hash,div;
               
        hash = receivedMessage.mod(oneThousand);    //Obtains hashed value appended to front of message
               
        BigInteger messageWithoutHash = receivedMessage.divide(oneThousand);        //Obtains message without hashed value
        String messageWithSecret = asciiToString(messageWithoutHash);               //Converts ASCII code back to String
               
        int strLeng = messageWithSecret.length();
        String message = messageWithSecret.substring(1,strLeng);        //Obtains message without secret
        String secret = messageWithSecret.substring(0,1);               //Obtains secret
        
        BigInteger checkHash = messageWithoutHash.mod(hashFunc);        //Obtains hashed value of message
        
        if(hash.compareTo(checkHash) == 0){
            messageStatus = true;
        }
           
        if(debugFlag ==true){
            System.out.println("\nRECEIVING_MAC");
            System.out.println("receivedMessage = "+receivedMessage);
            System.out.println("messageWithoutHash = "+messageWithoutHash);
            System.out.println("messageWithSecret = "+messageWithSecret);
            System.out.println("message = "+message);
            System.out.println("secret = "+secret);
            System.out.println("hash = "+hash);
            System.out.println("checkHash = "+checkHash);
            System.out.println("messageStatus = "+messageStatus);
        }
        
        return message;
    }
    
    public Boolean getMessageStatus() {
        return messageStatus;
    }
        
    public static void testMAC(){
        //TEST 1
        //Test for default constructor
        MAC testMac = new MAC();
        String message = "Hello World!";
        BigInteger hashFunc = new BigInteger("13");
        
        BigInteger sentMsg = testMac.send_MAC(message, hashFunc);
        String receivedMsg = testMac.receive_MAC(sentMsg, hashFunc);
        
        System.out.println("\n********MAC TEST 1***********");
        System.out.println("Original Message = "+message);
        System.out.println("Sent Message = "+sentMsg);
        System.out.println("Received Message = "+receivedMsg);
        
        if(testMac.messageStatus == true){
             System.out.println("Message is Authentic");
        }
        else{
            System.out.println("Message is NOT Authentic");
        }
        System.out.println("********END MAC TEST 1********\n");
        
        //TEST 2
        //Test with user defined secret
        MAC testMac2 = new MAC("!");
        BigInteger hashFunc2 = new BigInteger("1234");
        String message2 = "TestMessage.txt";
        BigInteger sentMsg2 = testMac2.send_MAC(message2, hashFunc2);
        String receivedMsg2 = testMac2.receive_MAC(sentMsg2, hashFunc2);
        
        System.out.println("\n********MAC TEST 2***********");
        System.out.println("Original Message = "+message2);
        System.out.println("Sent Message = "+sentMsg2);
        System.out.println("Received Message = "+receivedMsg2);
        
        if(testMac2.messageStatus == true){
             System.out.println("Message is Authentic");
        }
        else{
            System.out.println("Message is NOT Authentic");
        }
        System.out.println("********END MAC TEST 2********\n");
    }
    
}
