package com.asi.security.saml.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.asi.security.saml.api.SamlServices;

/*
 * Samples:
 * 
 * SP initiated SSO:
 * http://localhost:8080/saml/sso?backTo=urlencode(launchURL)
 * 
 * IP initiated SSO
 * http://localhost:8080/saml/callback
 *      - relayState = launchURL
 * 
 * Environment variables needed:
 * 
 * API_CORE_URL
 * API_SESSION_URL
 * ENCRYPT_KEY
 * 
 * ASI_SAML_ACS_URL (SAML ACS. eg http://localhost/saml/callback)
 * ASI_SAML_IDP_URL (demo for now. eg http://localhost/saml/idp)
 * 
 * ASI_SAML_PRIVATE_KEY
 * ASI_SAML_PUBLIC_KEY
 * {IDP}_SAML_PUBLIC_KEY
 * 
 */

@RestController
public class SamlController {
	
	@Autowired
	private SamlServices samlServices;
	
	@RequestMapping(value = "/{action}", method = { RequestMethod.GET, RequestMethod.POST })
	public void process(@PathVariable("action") String action, HttpServletRequest request, HttpServletResponse response) 
			throws Exception {
		samlServices.perform("/"+action, request, response);
	}
	
}

