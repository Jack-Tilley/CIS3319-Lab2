package src;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.util.Formatter;

public class HMACTest {
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

	private static String toHexString(byte[] bytes) {
		Formatter formatter = new Formatter();
		
		for (byte b : bytes) {
			formatter.format("%02x", b);
		}

		return formatter.toString();
	}

	public static String calculateRFC2104HMAC(String data, String key)
		throws SignatureException, NoSuchAlgorithmException, InvalidKeyException
	{
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
		Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
		mac.init(signingKey);
		return toHexString(mac.doFinal(data.getBytes()));
	}

	public static void main(String[] args) throws Exception {
		String hmac = calculateRFC2104HMAC("hello1", "test");

        if(hmac.equals("104152c5bfdca07bc633eebd46199f0255c9f49d")){
            System.out.println("Match: " + hmac);
        }
		System.out.println(hmac);
		assert hmac.equals("104152c5bfdca07bc633eebd46199f0255c9f49d");
	}
}    
    