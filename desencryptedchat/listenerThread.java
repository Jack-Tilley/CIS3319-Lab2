/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package desencryptedchat;

import java.net.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
/**
 *
 * @author woah dude
 */
public class listenerThread extends Thread{
    private Socket sock;
    private volatile boolean endFlag;
    private String privateKey = "";
    private String hmacKey = "";
    
    public listenerThread(Socket inSock){
        sock = inSock;
        endFlag = false;
    }
    
    @Override
    public void run() {
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            
            System.out.println("\nListener Thread Ready.");
            
            while(!endFlag){
                String received = in.readLine(); //incoming ciphertext
                String receivedHMAC = in.readLine();
//                System.out.println("received cyphertext: " + received);
                
                // DECRYPTION GOES HERE, PRINT OUT RESULTING PLAINTEXT INSTEAD OF received
                
                
                // we might need to allow input of a normal key below
                
                String key
                        = "00010011"
                        + "00110100"
                        + "01010111"
                        + "01111001"
                        + "10011011"
                        + "10111100"
                        + "11011111"
                        + "11110001";
                
                privateKey = DESencryptedChat.getKey();
                hmacKey = DESencryptedChat.getHMACKey();
                KeyGenerator kg = new KeyGenerator(privateKey);
                
                
                String[] ReversedRoundKeyArray = kg.keyGenerator(kg.getKey());
                
//                String[] ReversedRoundKeyArray = KeyGenerator.keyGenerator(KeyGenerator.getKey());
                
                ReversedRoundKeyArray = KeyGenerator.roundKeyArrayReversal(ReversedRoundKeyArray);
                String pt = EncryptDecrypt.Decrypt(received, ReversedRoundKeyArray);
                String printOut = ChatHelper.binaryStringToText(pt);
                
                String generatedHmac = "";
                try {
                    generatedHmac = EncryptDecrypt.generateHmac(printOut, hmacKey);
                } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                    Logger.getLogger(listenerThread.class.getName()).log(Level.SEVERE, null, ex);
                }
                
                System.out.println("---------------------------------------------------------------------------------------");
                System.out.println(sock.getInetAddress().toString() + ": has sent: " + printOut);
                System.out.println("\tPartner plain text sent: " + "ENTER HERE");
                
                System.out.println("\tKey: " + privateKey);
                System.out.println("\tHMAC Key: " + ChatHelper.textToBinaryString(hmacKey));
                
//                System.out.println("\tCyphertext received: " + received);
                System.out.println("\tActual Cyphertext trasnlated from binary: " + ChatHelper.binaryStringToText(received));
                System.out.println("\tPartner cypher text sent: " + "ENTER HERE");
                
                System.out.println("\tHMAC received: " + receivedHMAC);
                System.out.println("\tHMAC generated: " + generatedHmac);
                
                if (generatedHmac.equals(receivedHMAC)){
                    System.out.println("\tBoth HMACs match. This message is authentic.");      
                } else {
                    System.out.println("\tBoth HMACs DO NOT match. This message IS NOT authentic.");  
                }
                
                System.out.println("---------------------------------------------------------------------------------------");
                
                
                
            }
            
            sock.close();
            System.out.println("Server-aspect done running.");

            
        }
        catch(IOException e){
            
            System.out.print("\nListener thread: " + e);
            
            
        }
   }
    
    // called by other thread
    public void end(){
        endFlag = true;
    }
}
    

