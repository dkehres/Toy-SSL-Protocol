import java.net.*;
import java.io.*;
import cipher.CA;
import cipher.CBC;
import cipher.DigitalSignature;
import cipher.MAC;
import cipher.RSA;
import cipher.ShiftCipher;
import cis435proj.asciiConverter;
import java.math.BigInteger;
import protocol.Protocols.*;
import protocol.*;
import java.math.BigInteger;
import java.util.Random;

/**
 * This program is one end of a simple command-line interface chat program.
 * It acts as a client which makes a connection to a CLChatServer program.  
 * The computer to connect to must be given as a command-line argument to the
 * program.  The two ends of the connection
 * each send a HANDSHAKE string to the other, so that both ends can verify
 * that the program on the other end is of the right type.  Then the connected 
 * programs alternate sending messages to each other.  The client always sends 
 * the first message.  The user on either end can close the connection by 
 * entering the string "quit" when prompted for a message.  Note that the first 
 * character of any string sent over the connection must be 0 or 1; this
 * character is interpreted as a command for security purpose. 
 */
class ChatClient {

   /**
    * Port number on server, if none is specified on the command line.
    */
   static final int DEFAULT_PORT = 1728;

   /**
    * Handshake string. Each end of the connection sends this  string to the 
    * other just after the connection is opened.  This is done to confirm that 
    * the program on the other side of the connection is a CLChat program.
    */
   static final String HANDSHAKE = "CIS435535";

   /**
    * This character is prepended to every message that is sent.
    */
   static final char MESSAGE = '0'; //more like the type in SSL

   /**
    * This character is sent to the connected program when the user quits.
    */
   static final char CLOSE = '1';  //more like the type in SSL




   public static void main(String[] args) {
       
      String algoC, algoI;
      int Kc,Ks,Mc,Ms;
      Random rand = new Random();
      String computer = "localhost";  // The computer where the server is running,
                        // as specified on the command line.  It can
                        // be either an IP number or a domain name.

      int port = DEFAULT_PORT;   // The port on which the server listens.

      Socket connection;      // For communication with the server.

      BufferedReader incoming;  // Stream for receiving data from server.
      PrintWriter outgoing;     // Stream for sending data to server.
      String messageOut;        // A message to be sent to the server.
      String messageIn;         // A message received from the server.

      BufferedReader userInput; // A wrapper for System.in, for reading
                                  // lines of input from the user.

    
      /* Open a connetion to the server.  Create streams for 
         communication and exchange the handshake. */
      try {
         System.out.println("Connecting to " + computer + " on port " + port);
         connection = new Socket(computer,port);
         incoming = new BufferedReader(
                       new InputStreamReader(connection.getInputStream()) );
         outgoing = new PrintWriter(connection.getOutputStream());
         
         //******** START PROJECT 3 CLIENT CODE HERE ************* //
         String     clientHandshakePacket0, 
                    clientHandshakePacket1; 
         
         String     serverHandshakePacket0,
                    serverHandshakePacket1;
         
         int Nc = rand.nextInt(599)+1;
         int Ns = 0;
         int pre_master_secret = 1234;
         
         String[] packetParsed;
         //defined in as class var
         //String algoC, algoI;
                  
         // Create server RSA
         RSA rsa = new RSA();
         CA certificateAuthority = new CA();
         certificateAuthority.registerCertificate(rsa.getPublicKey(), "Bob", "it's really me");
         
         // Client packet 0
         // sending [Nc CBC MAC Shift Hash]
         String algo_list = "CBC MAC Shift Hash";
         clientHandshakePacket0 = Integer.toString(Nc) + " " + algo_list;
         outgoing.println(clientHandshakePacket0);
         System.out.println(clientHandshakePacket0);
         outgoing.flush();
         
         // Server packet 0
         // recieving [Ns algoC algoI cert]
         serverHandshakePacket0 = incoming.readLine();
         packetParsed = serverHandshakePacket0.split(" ");
         Ns = Integer.parseInt(packetParsed[0]);
         algoC = packetParsed[1];                           
         algoI = packetParsed[2];                           
         BigInteger cert = new BigInteger(packetParsed[3]); ;
         
         if(!certificateAuthority.validateKeyWithCertificate(rsa.getPublicKey(), cert))
         {
             throw new Exception("Failed to authenticate certificate!");
         }
         
         // Client packet 1
         clientHandshakePacket1 = rsa.rsaEncrypt(BigInteger.valueOf(pre_master_secret)).toString();
         outgoing.println(clientHandshakePacket1);
         System.out.println(clientHandshakePacket1);
         outgoing.flush();
         
         // Create SSL keys
         int master_secret = pre_master_secret * Nc * Ns; 
         System.out.println("Master Secret: " + master_secret);
         //Not sure about this approach       
         Ks = master_secret % 1357; System.out.println("Ks: " + Ks);
         Ms = master_secret % 7531; System.out.println("Ms: " + Ms);
         Kc = master_secret % 2468; System.out.println("Kc: " + Kc);
         Mc = master_secret % 8642; System.out.println("Mc: " + Mc);


         // Recieve server MAC
         serverHandshakePacket1 = incoming.readLine();
         BigInteger serverMAC = new BigInteger(serverHandshakePacket1);
         MAC mac = new MAC();
         BigInteger calculatedServerMAC = mac.send_MAC(clientHandshakePacket0 + serverHandshakePacket0 + clientHandshakePacket1, BigInteger.valueOf(Ms));
         
         if(!calculatedServerMAC.equals(serverMAC))
         {
             throw new Exception("MACs do not equal!");
         }
         
        // Send client MAC
         BigInteger generatedMac = mac.send_MAC(clientHandshakePacket0 + serverHandshakePacket0 + clientHandshakePacket1, BigInteger.valueOf(Mc));
         String clientMACPacket = generatedMac.toString();
         outgoing.println(clientMACPacket);
         outgoing.flush();
         System.out.println("Client MAC: " + generatedMac);
         
         
         
         // Connection Sucess!
         System.out.println("Connected.  Enter your first message.");
      }
      catch (Exception e) {
         System.out.println("An error occurred while opening connection.");
         System.out.println(e.toString());
         return;
      }

      /* Exchange messages with the other end of the connection until one side or 
         the other closes the connection.  This client program send the first message.
         After that,  messages alternate strictly back and forth. */
     
      try {
         BigInteger validationCode, authentication;
         userInput = new BufferedReader(new InputStreamReader(System.in));
         System.out.println("NOTE: Enter 'quit' to end the program.\n");
         while (true) {
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
                    int shift = Kc;
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
               outgoing.flush();
               connection.close();
               System.out.println("Connection closed.");
               break;
            }
            System.out.println("EncryptedMessageOut: "+ encryptedMessageOut);
            System.out.println("validationCode: "+ validationCode);
            outgoing.println(MESSAGE +" "+encryptedMessageOut+" "+validationCode);
            outgoing.flush();
            if (outgoing.checkError()) {
               throw new IOException("Error occurred while transmitting message.");
            }
            System.out.println("WAITING...");
            messageIn = incoming.readLine();
            //Need to split input on " "
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
                    BigInteger shift = new BigInteger(Integer.toString(Ks));
                    message = shiftCipher.unshift(new String(encryptedMessage.toByteArray()), shift.intValue());
                    authentication = new BigInteger(shiftCipher.unshift(new String(encryptedAuthentication.toByteArray()), shift.intValue()));
                    break;
                default:
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
            System.out.println("RECEIVED:  " + message);                    
         }
      }
      catch (Exception e) {
         System.out.println("Sorry, an error has occurred.  Connection lost.");
         System.out.println(e.toString());
         System.exit(1);
      }

   }  // end main()


} //end class ChatClient