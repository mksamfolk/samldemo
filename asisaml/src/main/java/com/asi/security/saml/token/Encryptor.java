package com.asi.security.saml.token;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class Encryptor {
	
	private Cipher encipher;
	private Cipher decipher;
	
	public Encryptor(String key, String initVector) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
			encipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			encipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
			decipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			decipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
		} catch (Exception ex) {
            ex.printStackTrace();
        }
	}
	
    public String encrypt(String value) {
        try {
            byte[] encrypted = encipher.doFinal(value.getBytes());
            return Base64.encodeBase64String(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public String decrypt(String encrypted) {
        try {
            byte[] original = decipher.doFinal(Base64.decodeBase64(encrypted));
            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

}