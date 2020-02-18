package desencryptedchat;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class SentMessage {

    private String sentPlainText;
    private byte[] sentCipherText;


    public SentMessage() {}

	public String getSentPlainText() {
        return sentPlainText;
    }

    public byte[] getSentCipherText() {
        return sentCipherText;
    }

    public void setSentPlainText(String sentPlainText) {
        this.sentPlainText = sentPlainText;
    }

    public void setSentCipherText(byte[] sentCipherText) {
        this.sentCipherText = sentCipherText;
    }

    public void encryptMessage(SentMessage sentMessage, SecretKey originalKey, Cipher desCipher) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        desCipher.init(Cipher.ENCRYPT_MODE, originalKey);
        byte[] text = sentMessage.getSentPlainText().getBytes();
        byte[] textEncrypted = desCipher.doFinal(text);
        sentMessage.setSentCipherText(textEncrypted);
    }

    public void displaySentData(SentMessage sentMessage, SecretKey originalKey) {
        System.out.println("Key: " + Base64.getEncoder().encodeToString(originalKey.getEncoded()));
        System.out.println("Original Plain Text: " + sentMessage.getSentPlainText());
        System.out.println("Sent Cipher Text: " + new String(sentMessage.getSentCipherText()));
    }
}
