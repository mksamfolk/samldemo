package com.asi.security.saml.controller;

import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.RequestAbstractType;

public class SamlRequestDecoder {

    @SuppressWarnings("rawtypes")
	public SamlRequestData decodeSamlRequest(BasicSAMLMessageContext messageContext) throws Exception {
		RequestAbstractType samlRequest = (RequestAbstractType)messageContext.getInboundSAMLMessage();
		SamlRequestData requestData = new SamlRequestData();
		requestData.setAcsURL(((AuthnRequest)samlRequest).getAssertionConsumerServiceURL());
		requestData.setRelayState(messageContext.getRelayState());
		requestData.setIssuerId(samlRequest.getIssuer().getValue());
		return requestData;
    }

}
