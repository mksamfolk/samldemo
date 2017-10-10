package com.asi.security.saml.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SamlController {
	
	@Autowired
	private SamlServices samlServices;
	
	
	// End user => GET http://asi.com/saml/sso ; browser return HTML.
	// <form target= method= >
	// window.form[0].submit();
	
	// return hidden auto form post with SAML XML message.
	// response.getWriter().write("<form method=.... ")
	// target will be the Idp SAML end point. eg. http://td/sso/idp
	
	@GetMapping("/sso")
	public void createSamlRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
		samlServices.createSamlRequest(request, response);
	}
	
	
	// This method is just for demonstration! because this should be implemented at the other end at IDP.
	// <form target= method= >
	// window.form[0].submit();
	
	// this method returns a hidden form post which target is SP ACS URL.
	// optionally, IDP will request user to login before generating this form post.
	
	// case 1: user already login, return the hidden form post directly to ACS with relayState and attributes..
	
	// case 2: user not login, it returns a login page.
	//         after login, return the hidden form post to ACS with relayState and attributes..
	
	
	@PostMapping("/idp")
	public void receiveSamlRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
		samlServices.receiveSamlRequest(request, response);
	}
	
	// This is SP ACS URL end point.
	// This is expecting a form post request also which is a SAML response. And the extract information from SAML response.
	// This service will be sure the subjectId is unique in Idp world.
	// which means no other end user can pretend to be the same subjectId. Then user is authenticated.
	// SP will create its own session. SP will forward the end user to the relayState location.
	
	@PostMapping("/callback")
	public void receiveSamlResponse(HttpServletRequest request, HttpServletResponse response) throws Exception {
		samlServices.receiveSamlResponse(request, response);
	}
	
}
