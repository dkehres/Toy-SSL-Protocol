/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package protocol;

/**
 *
 * @author jacobmonday
 */
public class Network {
    private Boolean hacked;
    private Packet packet;
    
    public Network() {
        hacked = false;
    }
    
    public Network(Boolean hacked) {
        this.hacked = hacked;
    }
    
    public void getPacketFromSender(Packet packet) {
        this.packet = packet;
        if (hacked) {
            packetGetHacked();
        }
    }
    
    public Packet deliverPacketToReceiver() {
        return packet;
    }
    
    private void packetGetHacked() {
        
    }
}
