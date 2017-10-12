package com.asi.security.saml.model;

public class SamlRequestData {
	
	private String issuerId = "ASI";
	
	private String acsURL;
	
	private String idpURL;
	
	private String relayState;

	public String getIssuerId() {
		return issuerId;
	}

	public void setIssuerID(String issuerId) {
		this.issuerId = issuerId;
	}

	public String getAcsURL() {
		return acsURL;
	}

	public void setAcsURL(String acsURL) {
		this.acsURL = acsURL;
	}

	public String getIdpURL() {
		return idpURL;
	}

	public void setIdpURL(String idpURL) {
		this.idpURL = idpURL;
	}

	public String getRelayState() {
		return relayState;
	}

	public void setRelayState(String relayState) {
		this.relayState = relayState;
	}

}
