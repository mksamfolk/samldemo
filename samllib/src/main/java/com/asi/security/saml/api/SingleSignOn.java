package com.asi.security.saml.api;

import javax.servlet.http.HttpServletResponse;

public interface SingleSignOn {

	public void process(String subject, String relayState, HttpServletResponse response) throws Exception;
	
}
