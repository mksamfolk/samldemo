package com.asi.security.saml.service;

import java.security.KeyException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.httpclient.NameValuePair;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.asi.security.saml.api.SamlConfig;
import com.asi.security.saml.model.SamlAcsData;

@Component
public class SamlAssertionConsumer {
	
	@Autowired
	private SamlConfig samlConfig;
	
	public SamlAcsData consumeAssertion(HttpServletRequest request) throws Exception {
		
		SamlAcsData acsData = new SamlAcsData();
		
		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
		HTTPPostDecoder decoder = new HTTPPostDecoder();
		decoder.decode(messageContext);
		
		String relayState = messageContext.getRelayState();
		
		Response samlResponse = (Response)messageContext.getInboundSAMLMessage();
		Assertion assertion = samlResponse.getAssertions().get(0);
		String idp = assertion.getIssuer().getValue();
		String subjectId = assertion.getSubject().getNameID().getValue();
		boolean status = isResponseStatusSccess(samlResponse);
		Collection<NameValuePair> attributes = retrieveAttributes(assertion);
		
		String idpPublicKey = samlConfig.getIdpPublicKey(idp);
		
		if (status && verifySignature(messageContext, idpPublicKey)) {
			acsData.setValid(true);
		} else {
			acsData.setValid(false);
		}
		
		acsData.setRelayState(relayState);
		acsData.setSubjectId(subjectId);
		
		return acsData;
	}
	
	private boolean isResponseStatusSccess(Response samlResponse) {
		StatusCode statusCode = samlResponse.getStatus().getStatusCode();
        if (statusCode.getValue().equals(StatusCode.SUCCESS_URI)) {
        	return true;
        } else {
        	return false;
        }
	}
	
	private Collection<NameValuePair> retrieveAttributes(Assertion assertion) {
		Collection<NameValuePair> attributes = new ArrayList<NameValuePair>();
		if ( assertion.getAttributeStatements() != null ) {
			for ( AttributeStatement attributeStatement : assertion.getAttributeStatements() ) {
				attributes.addAll(retrieveAttributes(attributeStatement));
			}
		}
		return attributes;
	}

	private Collection<NameValuePair> retrieveAttributes(AttributeStatement attributeStatement) {
		Collection<NameValuePair> attributes = new ArrayList<NameValuePair>();
		if ( attributeStatement.getAttributes() != null ) {
			for ( Attribute attribute : attributeStatement.getAttributes() ) {
				for ( XMLObject value : attribute.getAttributeValues() ) {
					NameValuePair pair = new NameValuePair(attribute.getName(), value.getDOM().getTextContent());
					attributes.add(pair);
				}
			}
		}
		return attributes;
	}
	
	@SuppressWarnings("rawtypes")
	public boolean verifySignature(BasicSAMLMessageContext messageContext, String publickey) throws Exception {
		boolean flag = false;
		Response samlResponse = (Response)messageContext.getInboundSAMLMessage();		
		Assertion assertion = samlResponse.getAssertions().get(0);
		if(assertion.getSignature() != null)
			flag = verifySignature(assertion.getSignature(), publickey);
		else{
			if(samlResponse.getSignature() != null)
				flag = verifySignature(samlResponse.getSignature(), publickey);
		}
			
		return flag;	
	}
	
	// verify Signature
	private boolean verifySignature(Signature signature, String publicKeyContent) throws KeyException {
		if ( signature == null )
			return false;
    	RSAPublicKey publicKey = SecurityHelper.buildJavaRSAPublicKey(publicKeyContent);
    	Credential credential = SecurityHelper.getSimpleCredential(publicKey, null);
    	SignatureValidator signatureValidator = new SignatureValidator(credential);
    	try {
    		signatureValidator.validate(signature);
    	} catch ( ValidationException ex ) {
    		return false;
    	}
    	return true;
    }
	
}
