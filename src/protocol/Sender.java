/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package protocol;

import cipher.*;
import java.math.BigInteger;
import protocol.Protocols.Validation;
import protocol.Protocols.Cipher;

/**
 *
 * @author jacobmonday
 */
public class Sender {
    
    private String message;
    private Cipher cipher;
    private Validation validation;
    
    private BigInteger cipherText;
    private BigInteger validationCode;
    private RSAKey key;
    
    BigInteger sessionKey;
    int[] sessionKeyArray;
    
    private Packet packet;
    private Network network;
    CA certificateAuthority;
    
    public Sender(Network network, CA certificateAuthority, RSAKey key) {
        this.network = network;
        this.certificateAuthority = certificateAuthority;
        this.key = key;
    }
    
    public void sendMessage(String message, Cipher cipher, Validation validation, BigInteger sessionKey, int[] sessionKeyArray) {
        System.out.println("SENDING MESSAGE: " + message);
        System.out.println(Protocols.stringForCipher(cipher));
        System.out.println(Protocols.stringForValidation(validation));
        generateMessage(message, cipher, validation, sessionKey, sessionKeyArray);
        processMessage();
        System.out.print(packet.packetToString());
        network.getPacketFromSender(packet);
    }
    
    private void generateMessage(String message, Cipher cipher, Validation validation, BigInteger sessionKey, int[] sessionKeyArray) {
        this.message = message;
        this.cipher = cipher;
        this.validation = validation;
        this.sessionKey = sessionKey;
        this.sessionKeyArray = sessionKeyArray;
    }
    
    private void processMessage() {
        BigInteger certificate = certificateAuthority.getCertificate("receiver");
        Boolean verify = certificateAuthority.validateKeyWithCertificate(key, certificate);
        if (!verify) {
            return;
        }
        doValidation();
        doCipher();
        switch (cipher) {
            case BlockCipher:
            case CBC:
            case Polyalphabetic:
                packet = new Packet(cipherText, validationCode, encryptSessionKeyArray());
                break;
            case Shift:
            case Substitution:
                packet = new Packet(cipherText, validationCode, encryptSessionKey());
                break;
        }
    }
    
    private void doCipher() {
        switch (cipher) {
            case BlockCipher:
                BlockCipher blockCipher = new BlockCipher(sessionKeyArray);
                cipherText = new BigInteger(blockCipher.encrypt(message).getBytes());
                validationCode = new BigInteger(blockCipher.encrypt(validationCode.toString()).getBytes());
                break;
            case CBC:
                CBC cbc = new CBC(sessionKeyArray);
                cipherText = new BigInteger(cbc.encrypt(message, Protocols.initC).getBytes());
                validationCode = new BigInteger(cbc.encrypt(validationCode.toString(), Protocols.initC).getBytes());
                break;
            case Polyalphabetic:
                PolyalphabeticCipher polyalphabetic = new PolyalphabeticCipher(sessionKeyArray);
                cipherText = new BigInteger(polyalphabetic.encrypt(message).getBytes());
                validationCode = new BigInteger(polyalphabetic.encrypt(validationCode.toString()).getBytes());
                break;
            case Shift:
                ShiftCipher shiftCipher = new ShiftCipher();
                int shift = sessionKey.intValue();
                cipherText = new BigInteger(shiftCipher.shift(message, shift).getBytes());
                validationCode = new BigInteger(shiftCipher.shift(validationCode.toString(), shift).getBytes());
                break;
            case Substitution:
                SubstitutionCipher substitutionCipher = new SubstitutionCipher(new String(sessionKey.toByteArray()));
                cipherText = substitutionCipher.SubstitutionCipherEncrypt(new BigInteger(message.getBytes()));
                validationCode = substitutionCipher.SubstitutionCipherEncrypt(validationCode);
                break;
        }
        
    }
    
     private BigInteger encryptSessionKey() {
         return RSA.rsaEncrypt(sessionKey, key);
     }
    
    private BigInteger[] encryptSessionKeyArray() {
        BigInteger[] encryptedSessionKeyArray = new BigInteger[sessionKeyArray.length];
        for (int i = 0; i < encryptedSessionKeyArray.length; i++) {
            encryptedSessionKeyArray[i] = RSA.rsaEncrypt(BigInteger.valueOf(sessionKeyArray[i]), key);
        }
        return encryptedSessionKeyArray;
    }
    
    private void doValidation() {
        BigInteger intMessage = new BigInteger(message.getBytes());
        switch(validation) {
            case MAC:
                MAC mac = new MAC(Protocols.secret);
                validationCode = mac.send_MAC(message, Protocols.hashFunc);
                break;
            case DigitalSignature:
                validationCode = DigitalSignature.DigitalSignatureEncrypt(intMessage, Protocols.hashFunc, key);
                break;
            case Hash:
                validationCode = DigitalSignature.hash(intMessage, Protocols.hashFunc);
                break;
        }
    }
    
}
