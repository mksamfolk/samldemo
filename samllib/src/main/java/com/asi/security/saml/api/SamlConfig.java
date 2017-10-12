package com.asi.security.saml.api;

public interface SamlConfig {
	
	default public String getSSOPath() {
		return "/sso";
	}

	default public String getACSPath() {
		return "/callback";
	}
	
	default public String getIDPPath() {
		return "/idp";
	}
	
	default public String getBackParam() {
		return "backTo";
	}
	
	public String getIdpPublicKey(String idp);
	
	public String getPrivateKey();
	
	public String getAcsURL();

	public String getIdpURL();

}
