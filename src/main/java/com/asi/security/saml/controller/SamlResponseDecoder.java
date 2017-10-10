package com.asi.security.saml.controller;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.httpclient.NameValuePair;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.XMLObject;

public class SamlResponseDecoder {
	
    /*
     * Note: example is based on https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUserManJavaDSIG
     */
    // decode Saml Response
	@SuppressWarnings("rawtypes")
	public SamlResponseData decodeSamlResponse(BasicSAMLMessageContext messageContext) throws Exception {
		Response samlResponse = (Response)messageContext.getInboundSAMLMessage();
		return decodeSamlResponse(samlResponse);
    }

	public SamlResponseData decodeSamlResponse(Response samlResponse)
			throws Exception {
		Assertion assertion = AssertionFinder.findAssertion(samlResponse);
		SamlResponseData responseData = new SamlResponseData();
		if ( assertion != null ) {
			responseData.setIssuerId(assertion.getIssuer().getValue());
			responseData.setSubjectId(assertion.getSubject().getNameID().getValue());
			responseData.setValid(isResponseStatusSccess(samlResponse));
			responseData.setAttributes(retrieveAttributes(assertion));
		}
		return responseData;
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

	// is Response Status Sccess
	private boolean isResponseStatusSccess(Response samlResponse) {
		StatusCode statusCode = samlResponse.getStatus().getStatusCode();
        if (statusCode.getValue().equals(StatusCode.SUCCESS_URI)) {
        	return true;
        } else {
        	return false;
        }
	}

}
