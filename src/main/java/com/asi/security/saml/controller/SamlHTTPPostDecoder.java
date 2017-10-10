package com.asi.security.saml.controller;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;

public class SamlHTTPPostDecoder {

	@SuppressWarnings("rawtypes")
	public BasicSAMLMessageContext decode(HttpServletRequest request) throws Exception {
		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
		HTTPPostDecoder decoder = new HTTPPostDecoder();
		decoder.decode(messageContext);
		return messageContext;
		
	}
	
	
}