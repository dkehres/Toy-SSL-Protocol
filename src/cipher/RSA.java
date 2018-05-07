/*
 * This file contains the code used for RSA encryption
 * Users will be able to generate keys by calling the constructor
 * Users are able to pass a String message and encrypt/decrypt 
 * using generated or previously existing keys <p>
 *
 * RSA
 *
 * @author: Dylan Kehres
 * @date: 3/2/2018
 */
package cipher;

import static cis435proj.asciiConverter.*;
import java.math.BigInteger;
import java.io.*;
import java.security.SecureRandom;
import java.util.Random;

/**
 *
 * @author Dylan
 */
public class RSA {
    //Constants used for RSA calculations
   private final static BigInteger two = new BigInteger("2");
   private final static Random random = new Random(1);
   private final static int BIT_LENGTH = 2048;

   //Class variables
   private BigInteger n;
   private BigInteger p;
   private BigInteger q;
   private BigInteger z;
   private BigInteger e;
   private BigInteger d;
   private RSAKey publicKey;
   private RSAKey privateKey;
   
   private boolean debugFlag = true;
   
   //Code referenced from http://www.sanfoundry.com/java-program-implement-rsa-algorithm/
   public RSA(){
       //Obtain large prime numbers that are random for p and q
        p = BigInteger.probablePrime(BIT_LENGTH/2, random);
        q = BigInteger.probablePrime(BIT_LENGTH/2, random);
        z = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));      //z=(p-1)(q-1)
        n = p.multiply(q);      //n=pq                              
        e  = BigInteger.probablePrime(BIT_LENGTH/2,random);     //Obtain large prime number that is random for e
        
        //Check that z and e are relatively prime
        while (z.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(z) < 0)
        {
            e.add(BigInteger.ONE);
        }
        
        d = e.modInverse(z);
        
        //Generate keys
        publicKey = new RSAKey(n,e);
        privateKey = new RSAKey(n,d);
    }
  
   //Code for user defined p and q
   //NOT CURRENTLY WORKING!
//   public RSA (BigInteger user_p, BigInteger user_q) {
//      p = user_p;
//      q = user_q;
//      n = p.multiply(q);
//      z = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
//      
//      e=two;
//      while(relativelyPrime(e,z) == false){
//          e = e.add(BigInteger.ONE) ;
//      };
//      
//      BigInteger a;
//      BigInteger r = z.mod(e);
//      BigInteger x = ((z.subtract(r)).divide(e));
//      
//      for(BigInteger i = (x.add(BigInteger.ONE)); i.compareTo(z.subtract(BigInteger.ONE)) != 1; i=i.add(BigInteger.ONE) ){
//          if(relativelyPrime(z,i) == true){
//              if((i.multiply(e)).mod(z).compareTo(BigInteger.ONE) == 0){
//                  d = i;
//                  break;
//              }
//          }
//      }
//      
//      //ed mod z = 1
//      //d = (zq + 1)/e
//   }
   
   //encrypt using generated keys
   public BigInteger rsaEncrypt(BigInteger inputText) {   
      return inputText.modPow(e, n);
   }
   
   //encrypt using existing key
   static public BigInteger rsaEncrypt(BigInteger inputText, RSAKey privateKey) {   
       return inputText.modPow(privateKey.getExponent(), privateKey.getN());
   }
   
   //decrypt using generated keys
   public BigInteger rsaDecrypt(BigInteger encryptedText) {      
      return encryptedText.modPow(d, n);
   }
   
   //decrypt using existing key
   static public BigInteger rsaDecrypt(BigInteger inputText, RSAKey publicKey) {   
       return inputText.modPow(publicKey.getExponent(), publicKey.getN());
   }

   //creates string containing all variables for key generation
   public String rsaToString() {
      String s = "";
      
      s += "p = " + p +"\n";
      s += "q = " + q +"\n";
      s += "n = " + n +"\n";
      s += "z = " + z +"\n";
      s += "e = " + e +"\n";
      s += "d = " + d +"\n";
      
      return s;
   }
   
   //Function to determine greatest common denominator
    private static BigInteger gcd(BigInteger a, BigInteger b) {
        BigInteger zero = new BigInteger("0");
        BigInteger t;
        while(b.compareTo(zero) != 0){
            t = a;
            a = b;
            b = t.mod(b);
        }
        
        return a;
    }
    
    //check if BigIntegers are relatively prime
    private static boolean relativelyPrime(BigInteger a, BigInteger b) {
        return gcd(a,b).compareTo(BigInteger.ONE) == 0;
    }
   
    public RSAKey getPublicKey(){
        return publicKey;
    }
    
    public RSAKey getPrivateKey(){
        return privateKey;
    }
    
   public static void testRSA(){
       //RSA TEST 1
        String inputMessage = "Hello world!!! Give me some $$$";
        String outputMessage = "";
        BigInteger inputText = strToAscii(inputMessage);        //convert string to ASCII
        BigInteger encrytpedText;
        BigInteger decrytpedText;
        RSA rsaTest = new RSA();        //generate keys

        System.out.println("\n********RSA TEST 1***********");
        
        System.out.println("RSA Input Message: "+inputMessage);
        System.out.println("RSA Input Text: "+inputText.toString());
        
        encrytpedText = rsaTest.rsaEncrypt(inputText);
        System.out.println("RSA Encrypted Text: "+encrytpedText.toString());
        
        decrytpedText = rsaTest.rsaDecrypt(encrytpedText);
        System.out.println("RSA Decrypted Text: "+decrytpedText.toString());
        
        outputMessage = asciiToString(decrytpedText);       //convert ASCII to string
        System.out.println("RSA Output Message: "+outputMessage);
        
        System.out.println("********END RSA TEST 1********\n");
        
        //RSA TEST 2
        String inputMessage2 = "Wassup Dudes? Let$ te$T $0M3 cIp3Rzzz !@#$%^&*()_+";
        String outputMessage2 = "";
        BigInteger inputText2 = strToAscii(inputMessage2);      //convert string to ASCII
        BigInteger encrytpedText2;
        BigInteger decrytpedText2;
        RSA rsaTest2 = new RSA();       //generate keys

        System.out.println("\n********RSA TEST 2***********");
        
        System.out.println("RSA Input Message: "+inputMessage2);
        System.out.println("RSA Input Text: "+inputText2.toString());
        
        encrytpedText2 = rsaTest2.rsaEncrypt(inputText2);
        System.out.println("RSA Encrypted Text: "+encrytpedText2.toString());
        
        decrytpedText2 = rsaTest2.rsaDecrypt(encrytpedText2);
        System.out.println("RSA Decrypted Text: "+decrytpedText2.toString());
        
        outputMessage2 = asciiToString(decrytpedText2);     //convert ASCII to string
        System.out.println("RSA Output Message: "+outputMessage2);
        
        System.out.println("********END RSA TEST 2********\n");
   }
}
