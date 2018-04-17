/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package protocol;

import java.math.BigInteger;
/**
 *
 * @author Dylan
 */
public class Packet {
    
    private BigInteger message;
    private BigInteger authentication;
    private BigInteger sessionKey;
    private BigInteger[] sessionBlockKey;
    
    public Packet(){
        message = new BigInteger("");
        authentication = new BigInteger("");
        sessionKey = new BigInteger("");
        sessionBlockKey = new BigInteger[0];
    }
    
    public Packet(BigInteger message, BigInteger authentication, BigInteger sessionKey){
        this.message = message;
        this.authentication = authentication;
        this.sessionKey = sessionKey;
    }
    
    public Packet(BigInteger message, BigInteger authentication, BigInteger[] sessionBlockKey){
        this.message = message;
        this.authentication = authentication;
        this.sessionBlockKey = sessionBlockKey;
    }
    
    public BigInteger getMessage(){
        return message;
    }
    
    public BigInteger getAuthentication(){
        return authentication;
    }
    
    public BigInteger getSessionKey(){
        return sessionKey;
    }
    
    public BigInteger[] getSessionBlockKey(){
        return sessionBlockKey;
    }
    
    public String packetToString(){
        String s = "";
        s+="Payload = "+message+"\n";
        s+="Authentication ="+authentication+"\n";
        s+="Session Key = "+sessionKey+"\n";
        s+="Session Block Key = \n";
        if (sessionBlockKey != null) {
            for (BigInteger big : sessionBlockKey) {
                s+=big+"\n";
            }
        }
        return s;
    }
    
}
