package com.asi.security.saml.api;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface SamlServices {

	public void perform(String action, HttpServletRequest request, HttpServletResponse response) throws Exception;
	
}
