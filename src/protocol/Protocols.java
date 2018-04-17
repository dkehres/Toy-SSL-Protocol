/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package protocol;

import java.math.BigInteger;

/**
 *
 * @author jacobmonday
 */
public interface Protocols {
    public enum Cipher {
        BlockCipher,
        CBC,
        Polyalphabetic,
        Shift,
        Substitution
    }
    
    public enum Validation {
        MAC,
        DigitalSignature,
        Hash
    }
    
    static public String stringForCipher(Cipher cipher) {
        switch (cipher) {
            case BlockCipher:
                return "BlockCipher";
            case CBC:
                return "CBC";
            case Polyalphabetic:
                return "Polyalphabetic";
            case Shift:
                return "Shift";
            case Substitution:
                return "Substitution";
        }
        return null;
    }
    
    static public String stringForValidation(Validation validation) {
        switch (validation) {
            case MAC:
                return "MAC";
            case DigitalSignature:
                return "DigitalSignature";
            case Hash:
                return "Hash";
        }
        return null;
    }
    
    // protocol constants
    
    static public byte initC = 0b00000001;
    static public String secret = "super secret";
    static public BigInteger hashFunc = new BigInteger("13");
}
