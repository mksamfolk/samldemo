package com.asi.security.saml.token;

public class EncryptorFactory {
	
	private static String encryptKey;
	
//	String initVector = "RandomInitVectoa"; // 16 bytes IV
	private static final String initVector = "Advisor_Software"; // 16 bytes IV
	
	public static Encryptor createEncryptor() throws Exception {
		Encryptor encryptor = new Encryptor(encryptKey, initVector);
		return encryptor;
	}

	public static void setEncryptKey(String encryptKey) {
		EncryptorFactory.encryptKey = encryptKey;
	}

}
