package com.asi.security.saml.service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.asi.security.saml.model.SamlRequestData;

@Component
public class SamlRequestEncoder {
	
	@Autowired
	private SamlObjectBuilder samlObjectBuilder;
	


	public SamlRequestEncoder(SamlObjectBuilder samlObjectBuilder) {
		this.samlObjectBuilder = samlObjectBuilder;
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public BasicSAMLMessageContext encodeHTTPPostSamlRequest(
			HttpServletRequest request, HttpServletResponse response,
			SamlRequestData requestData) throws Exception {
		
		HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);
		
		// Build issuer
        Issuer issuer = samlObjectBuilder.buildIssuer();
        issuer.setValue(requestData.getIssuerId());
        
		// Build message
		AuthnRequest samlMessage = samlObjectBuilder.buildAuthnRequest();
		samlMessage.setID("AuthnRequest");
		samlMessage.setIssuer(issuer);
		samlMessage.setVersion(SAMLVersion.VERSION_20);
		samlMessage.setIssueInstant(new DateTime(0));
		samlMessage.setAssertionConsumerServiceURL(requestData.getAcsURL());
		 
		// Build end point
		Endpoint samlEndpoint = samlObjectBuilder.buildEndpoint();
		samlEndpoint.setLocation(requestData.getIdpURL());
		 
		// Build message context
		BasicSAMLMessageContext messageContext = samlObjectBuilder.buildMessageContext();
		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setPeerEntityEndpoint(samlEndpoint);
		messageContext.setOutboundSAMLMessage(samlMessage);
		messageContext.setRelayState(requestData.getRelayState());
		
		return messageContext;
		
	}

}
