/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package desencryptedchat.old_server;


import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// Keith R Hudock & Genise Mears CIS3319 Lab 1

public class Client {
    public static void main(String[] args) throws Exception{

        /** Create Secret Key & message objects*/
        byte[] decodedKey = Base64.getDecoder().decode("bRp5Ixyo2bY=");
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
        SentMessage sentMessage = new SentMessage();
        ReceivedMessage receivedMessage = new ReceivedMessage();
        
        /** Attempt to connect with the server */
        Socket s = new Socket("localhost", 1408);
        
        /** Create data streams for input/output */
        DataOutputStream dout = new DataOutputStream(s.getOutputStream());
        DataInputStream din = new DataInputStream(s.getInputStream());
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

        /** Initialize Cipher for encryption/decryption */
        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        
        while(true)
        {
            
            /** Send to Server output */
            /** Encrypt plaintext given by the client */
            String so = br.readLine();
            sentMessage.setSentPlainText(so);
            sentMessage.encryptMessage(sentMessage, originalKey, desCipher);

            /** Display data to be sent by client side */            
            System.out.println("----------------------- Sent by Client -----------------------");
            sentMessage.displaySentData(sentMessage, originalKey);
            
            /** Write ciphertext to out stream to be received by the server */
            dout.writeUTF(sentMessage.getSentPlainText());
            dout.writeUTF(new String(Base64.getEncoder().encode(sentMessage.getSentCipherText())));

            String serverPlainText = din.readUTF();
            String serverCipherText = din.readUTF();
            byte[] serverReceivedCipherText = Base64.getDecoder().decode(serverCipherText);
            System.out.println("--------------------- Received by Server ---------------------");
            System.out.println("Received Cipher Text: " + new String(serverReceivedCipherText));
            System.out.println("Received Plain Text: " + serverPlainText);
            System.out.println("--------------------------------------------------------------\n");
            
            /** Receive ciphertext from the server side */ 
            String plainText = din.readUTF();          
            String cipherText = din.readUTF();
            byte[] receivedCipherText = Base64.getDecoder().decode(cipherText);
            sentMessage.setSentPlainText(plainText);
            sentMessage.setSentCipherText(receivedCipherText);
            /** Decrypt ciphertext given by the server */
            
            receivedMessage.setReceivedCipherText(receivedCipherText);
            receivedMessage.decryptMessage(receivedMessage, originalKey, desCipher);
            dout.writeUTF(receivedMessage.getReceivedPlainText());
            dout.writeUTF(new String(Base64.getEncoder().encode(receivedMessage.getReceivedCipherText())));
            
            /** Display data received by client side */
            System.out.println("----------------------- Sent by Server -----------------------");
            sentMessage.displaySentData(sentMessage, originalKey);
            System.out.println("--------------------- Received by Client ---------------------");
            receivedMessage.displayReceivedData(receivedMessage, originalKey);
            System.out.println("--------------------------------------------------------------\n");
    

            dout.flush();
            
             if(so.equalsIgnoreCase("exit")){
                break;
            }
        }
        s.close();
        
    }
}    
