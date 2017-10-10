package com.asi.security.saml.controller;

import java.util.Collection;

import org.apache.commons.httpclient.NameValuePair;

public class SamlResponseData {

	private String acsURL, relayState, subjectId, issuerId, responseTo;
	private boolean valid, withEncryption, signatureVerifed;
	private Collection<NameValuePair> attributes;

	public String getSubjectId() {
		return subjectId;
	}

	public void setSubjectId(String subjectId) {
		this.subjectId = subjectId;
	}

	public String getIssuerId() {
		return issuerId;
	}

	public void setIssuerId(String issuerId) {
		this.issuerId = issuerId;
	}

	public boolean isValid() {
		return valid;
	}

	public void setValid(boolean valid) {
		this.valid = valid;
	}

	public String getAcsURL() {
		return acsURL;
	}

	public void setAcsURL(String acsURL) {
		this.acsURL = acsURL;
	}

	public String getRelayState() {
		return relayState;
	}

	public void setRelayState(String relayState) {
		this.relayState = relayState;
	}

	public boolean isWithEncryption() {
		return withEncryption;
	}

	public void setWithEncryption(boolean withEncryption) {
		this.withEncryption = withEncryption;
	}

	public boolean isSignatureVerifed() {
		return signatureVerifed;
	}

	public void setSignatureVerifed(boolean signatureVerifed) {
		this.signatureVerifed = signatureVerifed;
	}

	public String getResponseTo() {
		return responseTo;
	}

	public void setResponseTo(String responseTo) {
		this.responseTo = responseTo;
	}

	public Collection<NameValuePair> getAttributes() {
		return attributes;
	}

	public void setAttributes(Collection<NameValuePair> attributes) {
		this.attributes = attributes;
	}
	
}
