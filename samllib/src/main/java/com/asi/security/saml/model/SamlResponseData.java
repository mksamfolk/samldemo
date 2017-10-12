package com.asi.security.saml.model;

public class SamlResponseData {
	
	private String issuerId = "ASI";
	
	private String subjectId;

	public String getIssuerId() {
		return issuerId;
	}

	public void setIssuerId(String issuerId) {
		this.issuerId = issuerId;
	}

	public String getSubjectId() {
		return subjectId;
	}

	public void setSubjectId(String subjectId) {
		this.subjectId = subjectId;
	}
	
}
