package com.asi.security.saml.token;

public class SessionInfo {
	
	String sessionId;
	String clientId;
	String clientSecret;
	String tenantName;
	String username;
	String advisorPermalinkId;
	boolean totpRequired = false;
	boolean resetPwdRequired = false;
	String encryptedClientSecret;
	int tokenType = 0;
	boolean nonSessionToken = false;
	
	public String getSessionId() {
		return sessionId;
	}
	public void setSessionId(String sessionId) {
		this.sessionId = sessionId;
	}
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
	public String getTenantName() {
		return tenantName;
	}
	public void setTenantName(String tenantName) {
		this.tenantName = tenantName;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getAdvisorPermalinkId() {
		return advisorPermalinkId;
	}
	public void setAdvisorPermalinkId(String advisorPermalinkId) {
		this.advisorPermalinkId = advisorPermalinkId;
	}
	public boolean isTotpRequired() {
		return totpRequired;
	}
	public void setTotpRequired(boolean totpRequired) {
		this.totpRequired = totpRequired;
	}
	public boolean isResetPwdRequired() {
		return resetPwdRequired;
	}
	public void setResetPwdRequired(boolean resetPwdRequired) {
		this.resetPwdRequired = resetPwdRequired;
	}
	public String getEncryptedClientSecret() {
		return encryptedClientSecret;
	}
	public void setEncryptedClientSecret(String encryptedClientSecret) {
		this.encryptedClientSecret = encryptedClientSecret;
	}
	public int getTokenType() {
		return tokenType;
	}
	public void setTokenType(int tokenType) {
		this.tokenType = tokenType;
	}
	public boolean isNonSessionToken() {
		return nonSessionToken;
	}
	public void setNonSessionToken(boolean nonSessionToken) {
		this.nonSessionToken = nonSessionToken;
	}

}
