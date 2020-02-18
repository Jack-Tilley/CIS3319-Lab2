package desencryptedchat;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class ReceivedMessage {
    private String receivedPlainText;
    private byte[] receivedCipherText;
    
    public ReceivedMessage() {}

    public String getReceivedPlainText() {
        return receivedPlainText;
    }

    public byte[] getReceivedCipherText() {
        return receivedCipherText;
    }

    public void setReceivedPlainText(String receivedPlainText) {
        this.receivedPlainText = receivedPlainText;
    }

    public void setReceivedCipherText(byte[] receivedCipherText) {
        this.receivedCipherText = receivedCipherText;
    }

    public void decryptMessage(ReceivedMessage receivedMessage, SecretKey originalKey, Cipher desCipher) throws NoSuchAlgorithmException,
    NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        desCipher.init(Cipher.DECRYPT_MODE, originalKey);
        byte[] text = receivedMessage.getReceivedCipherText();
        byte[] textDecrypted = desCipher.doFinal(text);
        receivedMessage.setReceivedPlainText(new String(textDecrypted));
    }

    public void displayReceivedData(ReceivedMessage receivedMessage, SecretKey originalKey) {
        System.out.println("Key: " + Base64.getEncoder().encodeToString(originalKey.getEncoded()));
        System.out.println("Received Cipher Text: " + new String(receivedMessage.getReceivedCipherText()));
        System.out.println("Received Plain Text: " + receivedMessage.getReceivedPlainText());
    }
    
}