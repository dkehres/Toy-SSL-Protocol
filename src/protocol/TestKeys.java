/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package protocol;

import java.math.BigInteger;
import protocol.Protocols.Cipher;

/**
 *
 * @author jacobmonday
 */
public interface TestKeys {
    static int[] shifts = {1, 2, 3};
    static int shiftValue = 4;
    static String substitution = "9876543210";
    static int[] blockMap = new int[]{
        // The above comment is the number the map coresponds to.
        // See the full map below
        // 0000 0001 0010 0011
           15,   9,   4,   8,
        // 0100 0101 0110 0111
           5,   3,   14,  13, 
        // 1000 1001 1010 1011
           10,  2,   6,   0,
        // 1100 1101 1110 1111
           12,  7,   11,  1
    };
    
    static public BigInteger getSessionKey(Cipher cipher) {
        switch (cipher) {
            case Shift:
                return BigInteger.valueOf(shiftValue);
            case Substitution:
                return new BigInteger(substitution.getBytes());
            default:
                return null;
        }
    }
    
    static public int[] getSessionKeyArray(Cipher cipher) {
        switch (cipher) {
            case BlockCipher:
                return blockMap;
            case CBC:
                return blockMap;
            case Polyalphabetic:
                return shifts;
            default:
                return null;
        }
    }
}
