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
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


// Keith R Hudock & Genise Mears CIS3319 Lab 1

public class Server {
    public static void main(String[]args) throws Exception{


        ServerSocket s = new ServerSocket(1408);
        Socket ss = s.accept();

        /** Create Secret Key & message objects */
        byte[] decodedKey = Base64.getDecoder().decode("bRp5Ixyo2bY=");
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
        SentMessage sentMessage = new SentMessage();
        ReceivedMessage receivedMessage = new ReceivedMessage();


        System.out.println("Connected to the client.");

        /** Create data streams for input/output */

        DataOutputStream dout = new DataOutputStream(ss.getOutputStream());
        DataInputStream in = new DataInputStream(ss.getInputStream());
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));


        /** Initialize Cipher for encryption/decryption */
        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        while(true){
            
            /** Receive ciphertext from the client side */
            String plainText = in.readUTF();
            String cipherText = in.readUTF();
            byte[] receivedCipherText = Base64.getDecoder().decode(cipherText);
            sentMessage.setSentPlainText(plainText);
            sentMessage.setSentCipherText(receivedCipherText);
            System.out.println("----------------------- Sent by Client -----------------------");
            sentMessage.displaySentData(sentMessage, originalKey);

            /** Decrypt ciphertext given by the client */
            receivedMessage.setReceivedCipherText(receivedCipherText);
            receivedMessage.decryptMessage(receivedMessage, originalKey, desCipher);
            dout.writeUTF(receivedMessage.getReceivedPlainText());
            dout.writeUTF(new String(Base64.getEncoder().encode(receivedMessage.getReceivedCipherText())));
            
            /** Display data received by server side */
            System.out.println("--------------------- Received by Server ---------------------");
            receivedMessage.displayReceivedData(receivedMessage, originalKey);
            System.out.println("--------------------------------------------------------------\n");

            /** Send to Client output */
            /** Encrypt plaintext given by the server */
            String so = br.readLine();
            sentMessage.setSentPlainText(so);
            sentMessage.encryptMessage(sentMessage, originalKey, desCipher);
            
            /** Display data to be sent by server side */  
            System.out.println("----------------------- Sent by Server -----------------------");
            sentMessage.displaySentData(sentMessage, originalKey);
            
            /** Write ciphertext to out stream to be received by the server */
            dout.writeUTF(sentMessage.getSentPlainText());
            dout.writeUTF(new String(Base64.getEncoder().encode(sentMessage.getSentCipherText())));

            String clientPlainText = in.readUTF();
            String clientCipherText = in.readUTF();
            byte[] clientReceivedCipherText = Base64.getDecoder().decode(clientCipherText);
            System.out.println("--------------------- Received by Client ---------------------");
            System.out.println("Received Cipher Text: " + new String(clientReceivedCipherText));
            System.out.println("Received Plain Text: " + clientPlainText);
            System.out.println("--------------------------------------------------------------\n");
            dout.flush();

            
            if(so.equalsIgnoreCase("exit")){

                break;
            }
        }
    ss.close();
    s.close();

   }
}
