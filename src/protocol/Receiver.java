/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package protocol;

import cipher.*;
import cis435proj.asciiConverter;
import java.math.BigInteger;
import protocol.Protocols.Validation;
import protocol.Protocols.Cipher;
/**
 *
 * @author jacobmonday
 */
public class Receiver {
    private Network network;
    private Packet packet;
    private Cipher cipher;
    private Validation validation;
    CA certificateAuthority;
    RSA rsa;
    private String message;
    private BigInteger authentication;
    private BigInteger sessionKey;
    private int[] sessionBlockKey;
    private BigInteger encryptedMessage;
    private BigInteger encryptedAuthentication;
    private BigInteger encryptedSessionKey;
    private BigInteger[] encryptedSessionBlockKey;
    private Boolean validationCheck;
    
    public Receiver(){
        rsa = null;
        certificateAuthority = null;
        network = null;
        packet = null;
        cipher = null;
        validation = null;
        encryptedMessage = null;
        encryptedAuthentication = null;
        encryptedSessionKey = null;
        message = "";
        authentication = null;
        sessionKey = null;
    }
    
    public Receiver(Network network, CA certificateAuthority, RSA rsa, Cipher cipher, Validation validation){
        this.rsa = rsa;
        this.certificateAuthority = certificateAuthority;
        this.network = network;
        packet = null;
        this.cipher = cipher;
        this.validation = validation;
        encryptedMessage = null;
        encryptedAuthentication = null;
        encryptedSessionKey = null;
        encryptedSessionBlockKey = null;
        message = "";
        authentication = null;
        sessionKey = null;
        sessionBlockKey = null;
        
        certificateAuthority.registerCertificate(rsa.getPublicKey(), "receiver", "it's really me");
    }
    
    public void receivePacket(){
        packet = network.deliverPacketToReceiver();
    }
    
    public void processPacket(){
        encryptedMessage = packet.getMessage();
        encryptedAuthentication = packet.getAuthentication();
        encryptedSessionKey = packet.getSessionKey();
        encryptedSessionBlockKey = packet.getSessionBlockKey();
    }
    
    public String getMessage(){
        doCipher();
        doValidation();
        if (validationCheck) {
            return message;
        } else {
            return "error";
        }
    }
    
    private void doCipher() {
        if (encryptedSessionKey != null) {
            sessionKey = rsa.rsaDecrypt(encryptedSessionKey);
        }
        
        if (encryptedSessionBlockKey != null) {
            sessionBlockKey = new int[encryptedSessionBlockKey.length];
            for(int i = 0; i<encryptedSessionBlockKey.length; i++){
                sessionBlockKey[i] = rsa.rsaDecrypt(encryptedSessionBlockKey[i]).intValue();
            }
        }
        
        switch (cipher) {
            case BlockCipher:
                BlockCipher blockCipher = new BlockCipher(sessionBlockKey);
                blockCipher.reverseMap();
                message = blockCipher.decrypt(new String(encryptedMessage.toByteArray()));
                authentication = new BigInteger(blockCipher.decrypt(new String(encryptedAuthentication.toByteArray())));
                break;
            case CBC:               
                CBC cbc = new CBC(sessionBlockKey);
                cbc.reverseMap();
                message = cbc.decrypt(new String(encryptedMessage.toByteArray()), Protocols.initC);
                authentication = new BigInteger(cbc.decrypt(new String(encryptedAuthentication.toByteArray()), Protocols.initC));
                break;
            case Polyalphabetic:
                PolyalphabeticCipher polyalphabetic = new PolyalphabeticCipher(sessionBlockKey);
                message = polyalphabetic.decrypt(new String(encryptedMessage.toByteArray()));
                authentication = new BigInteger(polyalphabetic.decrypt(new String(encryptedAuthentication.toByteArray())));
                break;
            case Shift:
                ShiftCipher shiftCipher = new ShiftCipher();
                int shift = sessionKey.intValue();
                message = shiftCipher.unshift(new String(encryptedMessage.toByteArray()), shift);
                authentication = new BigInteger(shiftCipher.unshift(new String(encryptedAuthentication.toByteArray()), shift));
                break;
            case Substitution:
                SubstitutionCipher substitutionCipher = new SubstitutionCipher(new String(sessionKey.toByteArray()));
                message = new String((substitutionCipher.SubstitutionCipherDecrypt(encryptedMessage)).toByteArray());
                authentication = substitutionCipher.SubstitutionCipherDecrypt(encryptedAuthentication);
                break;
        }
    }
    
    private void doValidation() {
        BigInteger intMessage = new BigInteger(message.getBytes());
        switch(validation) {
            case MAC:
                MAC mac = new MAC(Protocols.secret);
                mac.receive_MAC(authentication, Protocols.hashFunc);
                validationCheck = mac.getMessageStatus();
                break;
            case DigitalSignature:
                validationCheck = DigitalSignature.DigitalSignatureVerification(intMessage, authentication, Protocols.hashFunc, rsa.getPrivateKey());
                break;
            case Hash:
                validationCheck = authentication.equals(DigitalSignature.hash(intMessage, Protocols.hashFunc));
                break;
        }
        System.out.println(validationCheck ? "passed validation" : "failed validation");
    }
}
