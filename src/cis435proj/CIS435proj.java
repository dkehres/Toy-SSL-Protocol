/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cis435proj;

import cipher.CA;
import cipher.RSA;
import java.math.BigInteger;
import protocol.Protocols.*;
import protocol.*;

/**
 *
 * @author Jacob
 */
public class CIS435proj {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {     
        /*
        PolyalphabeticCipher.testPolyalphabetic();
        SubstitutionCipher.TestSubstitution();
        RSA.testRSA();
        DigitalSignature.TestDigitalSignature();
        RSA.testRSA();
        CA.testCA();
        asciiConverter.testAsciiConverter();
        MAC.testMAC();
        CBC.testCipherBlockChaining();
        BlockCipher.testBlockCipher();
        */
        Network network = new Network();
        
        CA certificateAuthority = new CA();
        RSA rsa = new RSA();
        String testMessage = "this is our test message";
        Sender sender = new Sender(network, certificateAuthority, rsa.getPublicKey());
        for (Cipher cipher : Cipher.values()) {
            for (Validation validation : Validation.values()) {
                Receiver receiver = new Receiver(network, certificateAuthority, rsa, cipher, validation);
                BigInteger sessionKey = TestKeys.getSessionKey(cipher);
                int [] sessionKeyArray = TestKeys.getSessionKeyArray(cipher);
                sender.sendMessage(testMessage, cipher, validation, sessionKey, sessionKeyArray);
                receiver.receivePacket();
                receiver.processPacket();
                System.out.println("RECEIVING MESSAGE: " + receiver.getMessage());
            }
        }
    }
    
}
