package com.asi.security.saml.service;

import javax.xml.namespace.QName;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.signature.Signature;
import org.springframework.stereotype.Component;

@Component
public class SamlObjectBuilder {

	private XMLObjectBuilderFactory builderFactory;

	public SamlObjectBuilder() {
		builderFactory = Configuration.getBuilderFactory();
	}
	
	public Issuer buildIssuer() {
        Issuer issuer = (Issuer) buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
        return issuer;
	}
	
	public AuthnRequest buildAuthnRequest() {
		SAMLObjectBuilder<AuthnRequest> responseBuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
		AuthnRequest samlMessage = responseBuilder.buildObject();
		return samlMessage;
	}
	
	public AuthnStatement buildAuthnStatement() {
		AuthnStatement authnStatement = (AuthnStatement) buildXMLObject(AuthnStatement.DEFAULT_ELEMENT_NAME);
		return authnStatement;
	}
	
	public AuthnContext buildAuthnContext() {
		AuthnContext authnContext = (AuthnContext) buildXMLObject(AuthnContext.DEFAULT_ELEMENT_NAME);
		return authnContext;
	}
	
	public AuthnContextClassRef buildAuthnContextClassRef() {
		 AuthnContextClassRef classRef = (AuthnContextClassRef) buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
	     classRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
	     return classRef;
	}
	
	public Audience buildAudience() {
        Audience audience = (Audience) buildXMLObject(Audience.DEFAULT_ELEMENT_NAME);
        return audience;
	}
	
	public AudienceRestriction buildAudienceRestriction() {
        AudienceRestriction audienceRestriction = (AudienceRestriction) buildXMLObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        return audienceRestriction;
	}
	
	public Conditions buildConditions() {
        Conditions conditions = (Conditions) buildXMLObject(Conditions.DEFAULT_ELEMENT_NAME);
        return conditions;
	}
	
	public Subject buildSubject() {
        Subject subject = (Subject) buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);
        return subject;
	}
	
	public NameID buildNameID() {
		NameID nameId = (NameID) buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
		nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
		return nameId;
	}
	
	public Endpoint buildEndpoint() {
		SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		Endpoint samlEndpoint = endpointBuilder.buildObject();
		return samlEndpoint;
	}
	
	public Assertion buildAssertion() {
        Assertion assertion = (Assertion) buildXMLObject(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.setID("assertionID");
        assertion.setVersion(SAMLVersion.VERSION_20);
        return assertion;
	}
	
	public AttributeStatement buildAttributeStatement() {
        AttributeStatement attributeStatement = (AttributeStatement) buildXMLObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
        return attributeStatement;
	}
	
	public Attribute buildAttribute() {
    	Attribute attribute = (Attribute) buildXMLObject(Attribute.DEFAULT_ELEMENT_NAME);
    	return attribute;
	}
	
	public StatusCode buildStatusCode() {
		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		StatusCode statusCode = statusCodeBuilder.buildObject();
		return statusCode;
	}
	
	public Status buildStatus() {
		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Status responseStatus = statusBuilder.buildObject();
		return responseStatus;
	}
	
	public Response buildResponse() {
		SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
		Response samlMessage = responseBuilder.buildObject();
		return samlMessage;
	}
	
	public XSString buildAttributeValue(String value) {
    	XSStringBuilder stringBuilder = (XSStringBuilder) builderFactory.getBuilder(XSString.TYPE_NAME);
    	XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
    	stringValue.setValue(value);
    	return stringValue;
	}
	
	public Signature buildSignature() {
	    Signature signature = (Signature) builderFactory
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);
	    return signature;
	}
	
	public BasicSAMLMessageContext buildMessageContext() {
		return new BasicSAMLMessageContext();
	}
	
    private XMLObject buildXMLObject(QName objectQName){
        XMLObjectBuilder builder = builderFactory.getBuilder(objectQName);
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
    }
}
