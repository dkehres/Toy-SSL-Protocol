import cipher.CA;
import cipher.CBC;
import cipher.DigitalSignature;
import cipher.MAC;
import cipher.RSA;
import cipher.ShiftCipher;
import cis435proj.asciiConverter;
import java.net.*;
import java.io.*;
import java.math.BigInteger;
import protocol.Protocols;
import protocol.TestKeys;
import java.util.Random;

/**
 * This program is one end of a simple command-line interface chat program.
 * It acts as a server which waits for a connection from the ChatClient 
 * program.  The port on which the server listens can be specified as a 
 * command-line argument.  
 * This program only supports one connection.  As soon as a connection is 
 * opened, the listening socket is closed down.  The two ends of the connection
 * each send a HANDSHAKE string to the other, so that both ends can verify
 * that the program on the other end is of the right type.  Then the connected 
 * programs alternate sending messages to each other.  The client always sends 
 * the first message.  The user on either end can close the connection by 
 * entering the string "quit" when prompted for a message.  Note that the first 
 * character of any string sent over the connection must be 0 or 1; this
 * character is interpreted as a command for security purpose
 */
public class ChatServer {

   /**
    * Port to listen on, if none is specified on the command line.
    */
   static final int DEFAULT_PORT = 1728;

   /**
    * Handshake string. Each end of the connection sends this  string to the 
    * other just after the connection is opened.  This is done to confirm that 
    * the program on the other side of the connection is a ChatClient program.
    */
   static final String HANDSHAKE = "CIS435535";

   /**
    * This character is prepended to every message that is sent.
    */
   static final char MESSAGE = '0'; //more like the type in SSL


   /**
    * This character is sent to the connected program when the user quits.
    */
   static final char CLOSE = '1'; //more like the type in SSL

   
   
   public static void main(String[] args) {

     Random rand = new Random();
       
      int port = DEFAULT_PORT;   // The port on which the server listens.

      ServerSocket listener;  // Listens for a connection request.
      Socket connection;      // For communication with the client.

      BufferedReader incoming;  // Stream for receiving data from client.
      PrintWriter outgoing;     // Stream for sending data to client.
      String messageOut;        // A message to be sent to the client.
      String messageIn;         // A message received from the client.
      int Ns = rand.nextInt(599)+1; //Server nonce
      int Nc; //Client nonce
      String[] packetParsed;
      String[] cipherList;
      String[] validationList;
      
      String        clientHandshakePacket0, 
                    clientHandshakePacket1,
                    clientMACPacket;
         
         String     serverHandshakePacket0,
                    serverMACPacket;
      
      BufferedReader userInput; // A wrapper for System.in, for reading
                                // lines of input from the user.

      String algoC, algoI;
      int Kc,Ks,Mc,Ms;
      
      /* Wait for a connection request.  When it arrives, close
           down the listener.  Create streams for communication
           and exchange the handshake. */

      try {
         listener = new ServerSocket(port);
         System.out.println("Listening on port " + listener.getLocalPort());
         connection = listener.accept();
         listener.close();  
         incoming = new BufferedReader( 
                        new InputStreamReader(connection.getInputStream()) );
         outgoing = new PrintWriter(connection.getOutputStream());
         /*
         outgoing.println(HANDSHAKE);  // Send handshake to client.
         outgoing.flush();
         messageIn = incoming.readLine();  // Receive handshake from client.
         if (! HANDSHAKE.equals(messageIn) ) {
            throw new Exception("Connected program is not a ChatClient!");
         }
         */
         System.out.println("Connected.  Waiting for the first message.");
         
         // ClientPacket0
         clientHandshakePacket0 = incoming.readLine();
         packetParsed = clientHandshakePacket0.split(" ");
         Nc = Integer.parseInt(packetParsed[0]);
         cipherList = new String[(packetParsed.length - 1) / 2];
         int listIndex = 0;
         for (int i = 1; i < packetParsed.length; i += 2) {
             cipherList[listIndex] = packetParsed[i];
             listIndex++;
         }
         validationList = new String[(packetParsed.length - 1) / 2];
         listIndex = 0;
         for (int i = 2; i < packetParsed.length; i += 2) {
             validationList[listIndex] = packetParsed[i];
             listIndex++;
         }
         
         algoC = cipherList[1];
         algoI = validationList[1];
         
         // ServerPacket0
         RSA rsa = new RSA();
         CA certificateAuthority = new CA();
         certificateAuthority.registerCertificate(rsa.getPublicKey(), "Bob", "it's really me");
         serverHandshakePacket0 = Ns + " " + cipherList[1] + " " + validationList[1] + " " + certificateAuthority.getCertificate("Bob").toString();
         
         outgoing.println(serverHandshakePacket0);
         outgoing.flush();
         System.out.println("ServerPacket0: " + serverHandshakePacket0);
         
         // ClientPacket1
         clientHandshakePacket1 = incoming.readLine();
         BigInteger pre_master_secret = rsa.rsaDecrypt(new BigInteger(clientHandshakePacket1));
         
         // Create SSL keys
         int master_secret = pre_master_secret.intValue() * Nc * Ns; 
         System.out.println("Master Secret: " + master_secret);
         Ks = master_secret % 1357; System.out.println("Ks: " + Ks);
         Ms = master_secret % 7531; System.out.println("Ms: " + Ms);
         Kc = master_secret % 2468; System.out.println("Kc: " + Kc);
         Mc = master_secret % 8642; System.out.println("Mc: " + Mc);
         
         // Server MAC
         MAC mac = new MAC();
         BigInteger generatedMac = mac.send_MAC(clientHandshakePacket0 + serverHandshakePacket0 + clientHandshakePacket1, BigInteger.valueOf(Ms));
         serverMACPacket = generatedMac.toString();
         outgoing.println(serverMACPacket);
         outgoing.flush();
         System.out.println("Server MAC: " + generatedMac);
         
         // Recieve Client MAC
         String receivedMAC = incoming.readLine();
         BigInteger clientMAC = new BigInteger(receivedMAC);
         BigInteger calculatedClientMAC = mac.send_MAC(clientHandshakePacket0 + serverHandshakePacket0 + clientHandshakePacket1, BigInteger.valueOf(Mc));
         
         if(!calculatedClientMAC.equals(clientMAC))
         {
             throw new Exception("MACs do not equal!");
         }
      }
      catch (Exception e) {
         System.out.println("An error occurred while opening connection.");
         System.out.println(e.toString());
         return;
      }

      /* Exchange messages with the other end of the connection until one side
         or the other closes the connection.  This server program waits for 
         the first message from the client.  After that, messages alternate 
         strictly back and forth. */

      try {
         BigInteger validationCode, authentication;
         userInput = new BufferedReader(new InputStreamReader(System.in));
         System.out.println("NOTE: Enter 'quit' to end the program.\n");
         while (true) {
            System.out.println("WAITING...");
            messageIn = incoming.readLine();
            
            String[] parsedEncryptedMessage = messageIn.split(" ");
            BigInteger encryptedCloser = new BigInteger(parsedEncryptedMessage[0]);
            String closer = encryptedCloser.toString();
            if (messageIn.length() > 0) {
                   // The first character of the message is a command. If 
                   // the command is CLOSE, then the connection is closed.  
                   // Otherwise, remove the command character from the 
                   // message and procede.
               if (closer.charAt(0) == CLOSE) {
                  System.out.println("Connection closed at other end.");
                  connection.close();
                  break;
               }
               //messageIn = messageIn.substring(1);
            }
            
            BigInteger encryptedMessage = new BigInteger(parsedEncryptedMessage[1]);
            BigInteger encryptedAuthentication = new BigInteger(parsedEncryptedMessage[2]);
            
            String message;
            
            //MESSAGE DECRYPTION
            
            switch(algoC){
                case "CBC":
                    CBC cbc = new CBC(TestKeys.getSessionKeyArray(algoC));
                    cbc.reverseMap();
                    message = cbc.decrypt(new String(encryptedMessage.toByteArray()), Protocols.initC);
                    authentication = new BigInteger(cbc.decrypt(new String(encryptedAuthentication.toByteArray()), Protocols.initC));
                    break;
                case "Shift":
                    ShiftCipher shiftCipher = new ShiftCipher();
                    BigInteger shift = new BigInteger(Integer.toString(Kc));
                    message = shiftCipher.unshift(new String(encryptedMessage.toByteArray()), shift.intValue());
                    authentication = new BigInteger(shiftCipher.unshift(new String(encryptedAuthentication.toByteArray()), shift.intValue()));
                    break;
                default:
                    closer = Character.toString(CLOSE);
                    message = null;
                    authentication = null;
                    break;
            }
            
        Boolean validationCheck;
        switch(algoI) {
            case "MAC":
                MAC mac = new MAC(Protocols.secret);
                mac.receive_MAC(authentication, Protocols.hashFunc);
                validationCheck = mac.getMessageStatus();
                break;
            case "Hash":
                validationCheck = authentication.equals(DigitalSignature.hash(asciiConverter.strToAscii(message), Protocols.hashFunc));
                break;
            default:
                validationCheck = false;
        }
        System.out.println(validationCheck ? "passed validation" : "failed validation");
            
            System.out.println("RECEIVED:  " + message);
            System.out.print("SEND:      ");
            messageOut = userInput.readLine();
            
             //MESSAGE ENCRYPTION
            switch(algoI){
                case "MAC":
                    MAC mac = new MAC(Protocols.secret);
                    validationCode = mac.send_MAC(messageOut, Protocols.hashFunc);
                    break;
                case "Hash":
                    validationCode = DigitalSignature.hash(asciiConverter.strToAscii(messageOut), Protocols.hashFunc);
                    break;
                default:
                    validationCode = null;
                    break;
            }

            BigInteger encryptedMessageOut;
            switch(algoC){
                case "CBC":
                    CBC cbc = new CBC(TestKeys.getSessionKeyArray(algoC));
                    encryptedMessageOut = new BigInteger(cbc.encrypt(messageOut, Protocols.initC).getBytes());
                    validationCode = new BigInteger(cbc.encrypt(validationCode.toString(), Protocols.initC).getBytes());
                    break;
                case "Shift":
                    ShiftCipher shiftCipher = new ShiftCipher();
                    int shift = Ks;
                    encryptedMessageOut = new BigInteger(shiftCipher.shift(messageOut, shift).getBytes());
                    validationCode = new BigInteger(shiftCipher.shift(validationCode.toString(), shift).getBytes());
                    break;
                default:
                    encryptedMessageOut = null;
                    validationCode = null;
                    break;
            }
            
            if (messageOut.equalsIgnoreCase("quit"))  {
                  // User wants to quit.  Inform the other side
                  // of the connection, then close the connection.
               outgoing.println(CLOSE);
               outgoing.flush();  // Make sure the data is sent!
               connection.close();
               System.out.println("Connection closed.");
               break;
            }
            System.out.println("EncryptedMessageOut: "+ encryptedMessageOut);
            System.out.println("validationCode: "+ validationCode);
            outgoing.println(MESSAGE + " "+encryptedMessageOut+" "+validationCode);
            outgoing.flush(); // Make sure the data is sent!
            if (outgoing.checkError()) {
               throw new IOException("Error occurred while transmitting message.");
            }
         }
      }
      catch (Exception e) {
         System.out.println("Sorry, an error has occurred.  Connection lost.");
         System.out.println("Error:  " + e);
         System.exit(1);
      }

   }  // end main()

    private static BigInteger BigInteger() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }



} //end class ChatServer