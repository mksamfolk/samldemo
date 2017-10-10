package com.asi.security.saml.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SamlController {
	
	public SamlController() throws Exception {
		DefaultBootstrap.bootstrap();
	}
	
	// End user => GET http://asi.com/saml/sso ; browser return HTML.
	// <form target= method= >
	// window.form[0].submit();
	
	// return hidden auto form post with SAML XML message.
	// response.getWriter().write("<form method=.... ")
	// target will be the Idp SAML end point. eg. http://td/sso/idp
	
	@GetMapping("/sso")
	public void createSamlRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
		SamlHTTPPostEncoder samlHTTPPostEncoder = new SamlHTTPPostEncoder();
		BasicSAMLMessageContext messageContext = createSamlRequestContext(request);
		samlHTTPPostEncoder.encode(messageContext, response);
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
		SamlHTTPPostDecoder samlHTTPPostDecoder = new SamlHTTPPostDecoder();
		SamlRequestDecoder samlRequestDecoder = new SamlRequestDecoder();
		BasicSAMLMessageContext requestContext = samlHTTPPostDecoder.decode(request);
		SamlRequestData requestData = samlRequestDecoder.decodeSamlRequest(requestContext);
		createSamlResponse(request, "testIdp", response, requestData);
	}
	
	// This is SP ACS URL end point.
	// This is expecting a form post request also which is a SAML response. And the extract information from SAML response.
	// This service will be sure the subjectId is unique in Idp world.
	// which means no other end user can pretend to be the same subjectId. Then user is authenticated.
	// SP will create its own session. SP will forward the end user to the relayState location.
	
	@PostMapping("/callback")
	public void receiveSamlResponse(HttpServletRequest request, HttpServletResponse response)
	throws Exception {
		SamlHTTPPostDecoder samlHTTPPostDecoder = new SamlHTTPPostDecoder();
		SamlResponseDecoder samlResponseDecoder = new SamlResponseDecoder();
		BasicSAMLMessageContext requestContext = samlHTTPPostDecoder.decode(request);
		SamlResponseData responseData = samlResponseDecoder.decodeSamlResponse(requestContext);
//		verifySignature(requestContext, responseData);
		response.getWriter().write("done");
	}
	
	public void createSamlResponse(HttpServletRequest request, String issuerId, HttpServletResponse response, SamlRequestData requestData) throws Exception {
		SamlHTTPPostEncoder samlHTTPPostEncoder = new SamlHTTPPostEncoder();
		SamlResponseCreator samlResponseCreator = new SamlResponseCreator();
		
		String privateKey = "";
		SamlResponseData responseData = new SamlResponseData();
		responseData.setAcsURL(requestData.getAcsURL());
		responseData.setIssuerId(issuerId);
		responseData.setResponseTo(requestData.getIssuerId());
		responseData.setRelayState(requestData.getRelayState());
		responseData.setValid(true);
		
		BasicSAMLMessageContext responseContext = samlResponseCreator.encodeSamlResponseMessage(responseData);
//		if ( privateKey != null )
//			samlResponseSigner.signResponseAssertion(responseContext, privateKey);
		samlHTTPPostEncoder.encode(responseContext, response);
	}
	
	private BasicSAMLMessageContext createSamlRequestContext(
			HttpServletRequest request) throws Exception {
		
		SamlRequestCreator samlRequestCreator = new SamlRequestCreator();
		String idProvider = "http://localhost:8080/saml/idp";
		String relayState = "https://www.google.com/";
		SamlRequestData requestData = new SamlRequestData();
		requestData.setAcsURL(buildAcsURL(request));
		requestData.setIdProvider(idProvider);
		requestData.setRelayState(relayState);
		BasicSAMLMessageContext messageContext = samlRequestCreator.encodeSamlRequestMessage(requestData);
		return messageContext;
	}
	
	private String buildAcsURL(HttpServletRequest request) {
		String scheme = request.getScheme();
		String servername = request.getServerName();
		int serverPort = request.getServerPort();
		String contextPath = request.getContextPath();
		String servicePath = scheme + "://" + servername + getRequestURLPort(scheme, serverPort) + contextPath;
		String acsURL = servicePath + "/callback";
		return acsURL;
	}
	
	private String getRequestURLPort(String scheme, int serverPort) {
		if ( ("http".equalsIgnoreCase(scheme) && serverPort == 80) || 
				("https".equalsIgnoreCase(scheme) && serverPort == 443) ) {
			return "";
		} else {
			return ":" + serverPort;
		}
	}
	
	
}
