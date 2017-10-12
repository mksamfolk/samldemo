package com.asi.security.saml.token;

//import java.net.URLEncoder;
//
//import org.json.JSONObject;

public class ClientSecretEncryptor {
	
	private String clientId;
	
	private String clientSecret;
	
	private String encryptedClientSecret;
	
	private String advisorPermalinkId;
	
	// private String encryptedURL;
	
	public void encrypt(Encryptor encryptor) {
//		JSONObject jobj = new JSONObject();
//		jobj.put("clientId", clientId);
//		jobj.put("clientSecret", clientSecret);
//		this.encryptedClientSecret = encryptor.encrypt(jobj.toString());
		
		if (advisorPermalinkId == null) {
			encryptedClientSecret = encryptor.encrypt(clientId + " " + clientSecret);
		} else {
			encryptedClientSecret = encryptor.encrypt(clientId + " " + clientSecret + " " +
				advisorPermalinkId);
		}
	}

	public void decrypt(Encryptor encryptor) {
//		String decrypted = encryptor.decrypt(encryptedClientSecret);
//		JSONObject jobj = new JSONObject(decrypted);
//		this.clientId = jobj.getString("clientId");
//		this.clientSecret = jobj.getString("clientSecret");

		String idAndSecret = encryptor.decrypt(encryptedClientSecret);
		String[] pair = idAndSecret.split(" ");
		this.clientId = pair[0];
		this.clientSecret = pair[1];
		
		if (pair.length > 2) {
			this.advisorPermalinkId = pair[2];
		}
	}

//	public void urlencrypt(Encryptor encryptor) throws Exception {
//		encryptedURL = URLEncoder.encode(encryptor.encrypt(clientId + " " + clientSecret), "UTF-8");
//	}
//
//	public void urldecrypt(Encryptor encryptor) {
//		String idAndSecret = encryptor.decrypt(encryptedURL);
//		String[] pair = idAndSecret.split(" ");
//		this.clientId = pair[0];
//		this.clientSecret = pair[1];
//	}
	
	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getEncryptedClientSecret() {
		return encryptedClientSecret;
	}

	public void setEncryptedClientSecret(String encryptedClientSecret) {
		this.encryptedClientSecret = encryptedClientSecret;
	}

	public String getAdvisorPermalinkId() {
		return advisorPermalinkId;
	}

	public void setAdvisorPermalinkId(String advisorPermalinkId) {
		this.advisorPermalinkId = advisorPermalinkId;
	}
	
//	public String getEncryptedURL() {
//		return encryptedURL;
//	}
//
//	public void setEncryptedURL(String encryptedURL) {
//		this.encryptedURL = encryptedURL;
//	}
	
}
