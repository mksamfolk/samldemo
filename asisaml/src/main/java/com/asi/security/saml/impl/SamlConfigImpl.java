package com.asi.security.saml.impl;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.asi.security.saml.api.SamlConfig;

@Component
public class SamlConfigImpl implements SamlConfig {
	
	public static final String SSO_PATH = "/sso"; 

	public static final String ACS_PATH = "/callback"; 

	public static final String IDP_PATH = "/idp"; 

	@Value("${ASI_SAML_ACS_URL}")
	private String acsURL;
	
	@Value("${ASI_SAML_IDP_URL}")
	private String idpURL;
	
	@Value("${BACK_TO_PARAM:backTo}")
	private String backParam;

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

	public String getBackParam() {
		return backParam;
	}

	public void setBackParam(String backParam) {
		this.backParam = backParam;
	}
	
}
