package com.asi.security.saml.controller;


import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;

public class SamlResponseCreator {

    public SamlResponseCreator() {
		super();
	}
    
    @SuppressWarnings("rawtypes")
    public BasicSAMLMessageContext encodeSamlResponseMessage(SamlResponseData responseData) throws Exception {
        Response samlMessage = createResponse(responseData.getAcsURL(), responseData.getSubjectId(), responseData.getIssuerId(), responseData.getResponseTo(), responseData.isValid());
		Endpoint samlEndpoint = createEndPoint(responseData.getAcsURL());
		BasicSAMLMessageContext messageContext = createMessageContext(samlMessage, samlEndpoint, responseData.getRelayState());
		return messageContext;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private BasicSAMLMessageContext createMessageContext(
			Response samlMessage,
			Endpoint samlEndpoint, String relayState) {
		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setPeerEntityEndpoint(samlEndpoint);
		messageContext.setOutboundSAMLMessage(samlMessage);
		messageContext.setRelayState(relayState);
       ((SAMLMessageContext) messageContext).setInboundSAMLMessageAuthenticated(true);
		return messageContext;
	}

	@SuppressWarnings("unchecked")
	private Endpoint createEndPoint(String acsURL) {
		SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) Configuration.getBuilderFactory()
		        .getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		Endpoint samlEndpoint = endpointBuilder.buildObject();
		samlEndpoint.setLocation(acsURL);
		return samlEndpoint;
	}

	@SuppressWarnings("unchecked")
	private Response createResponse(String acsURL, String subjectId, String issuerId, String responseTo, boolean valid) throws Exception {
		SAMLObjectBuilder<Response> responseBuilder = 
			(SAMLObjectBuilder<Response>) Configuration.getBuilderFactory()
		        .getBuilder(Response.DEFAULT_ELEMENT_NAME);
		Response samlMessage = responseBuilder.buildObject();
		samlMessage.setID(issuerId);
		samlMessage.setInResponseTo(responseTo);
		samlMessage.setVersion(SAMLVersion.VERSION_20);
		samlMessage.setIssueInstant(new DateTime());
		samlMessage.setDestination(acsURL);
		samlMessage.setStatus(createResponseStatus(valid));
		samlMessage.getAssertions().add(createAssertion(acsURL, subjectId, issuerId));
		
		return samlMessage;
	}

	@SuppressWarnings("unchecked")
	private Status createResponseStatus(boolean valid) {
		StatusCode statusCode = createStatusCode(valid);
		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) Configuration.getBuilderFactory()
		        .getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Status responseStatus = statusBuilder.buildObject();
		responseStatus.setStatusCode(statusCode);
		return responseStatus;
	}

	@SuppressWarnings("unchecked")
	private StatusCode createStatusCode(boolean valid) {
		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) Configuration.getBuilderFactory()
        .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		StatusCode statusCode = statusCodeBuilder.buildObject();
		if ( valid )
			statusCode.setValue(StatusCode.SUCCESS_URI);
		else
			statusCode.setValue(StatusCode.AUTHN_FAILED_URI);
		return statusCode;
	}
	
	private Issuer createIssuer(String issuerId) {
        QName qname = new QName(SAMLConstants.SAML20_NS, Issuer.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
        Issuer issuer = (Issuer) buildXMLObject(qname);
		issuer.setValue(issuerId);
		return issuer;
	}
	
	private Assertion createAssertion(String acsURL, String subjectId, String issuerId) throws Exception {
        QName qname = new QName(SAMLConstants.SAML20_NS, Assertion.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
        Assertion assertion = (Assertion) buildXMLObject(qname);
        assertion.setIssueInstant(new DateTime(0));
        assertion.setID("sessionIdentifier");
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(createIssuer(issuerId));
        assertion.getAuthnStatements().add(createAuthnStatement());
        assertion.getAttributeStatements().add(createUserIdAttributeStatement());
        assertion.setConditions(createConditions(acsURL));
        assertion.setSubject(createSubject(subjectId));
		return assertion;
	}
	
	private AuthnStatement createAuthnStatement() {
		AuthnStatement authnStatement = 
	            (AuthnStatement) buildXMLObject(AuthnStatement.DEFAULT_ELEMENT_NAME);
		authnStatement.setAuthnInstant( new DateTime());
		authnStatement.setSessionNotOnOrAfter(new DateTime());
		authnStatement.setAuthnContext(createAuthnContext());
		return authnStatement;
	}

	private AuthnContext createAuthnContext() {
		AuthnContext authnContext = 
            (AuthnContext) buildXMLObject(AuthnContext.DEFAULT_ELEMENT_NAME);
		authnContext.setAuthnContextClassRef(createAuthnContextClassRef());
		return authnContext;
	}

	private AuthnContextClassRef createAuthnContextClassRef() {
		 AuthnContextClassRef classRef = (AuthnContextClassRef) buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
	     classRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
		return classRef;
	}

	private Conditions createConditions(String acsURL) {
        QName qname = new QName(SAMLConstants.SAML20_NS, Conditions.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
        Conditions conditions = (Conditions) buildXMLObject(qname);
        conditions.getAudienceRestrictions().add(createAudienceRestriction(acsURL));
		return conditions;
	}
	
	private AudienceRestriction createAudienceRestriction(String acsURL) {
        QName qname = new QName(SAMLConstants.SAML20_NS, AudienceRestriction.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
        AudienceRestriction audienceRestriction = (AudienceRestriction) buildXMLObject(qname);
        audienceRestriction.getAudiences().add(createAudience(acsURL));
		return audienceRestriction;
	}
	
	private Audience createAudience(String acsURL) {
        QName qname = new QName(SAMLConstants.SAML20_NS, Audience.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
        Audience audience = (Audience) buildXMLObject(qname);
        audience.setAudienceURI(acsURL);
		return audience;
	}
	
	private Subject createSubject(String subjectId) {
        QName qname = new QName(SAMLConstants.SAML20_NS, Subject.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
        Subject subject = (Subject) buildXMLObject(qname);
        subject.setNameID(createNameID(subjectId));
		return subject;
	}
	
	private NameID createNameID(String subjectId){
		QName qname = new QName(SAMLConstants.SAML20_NS, NameID.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
		NameID nameId = (NameID) buildXMLObject(qname);
		nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
		nameId.setValue(subjectId);
		return nameId;
	}
	private AttributeStatement createUserIdAttributeStatement() {
        AttributeStatement attributeStatement = 
            (AttributeStatement) buildXMLObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
        attributeStatement.getAttributes().add(createTestAttribute());
		return attributeStatement;
	}
	
    private Attribute createTestAttribute() {
    	QName qname = new QName(SAMLConstants.SAML20_NS, Attribute.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
    	Attribute attribute = (Attribute) buildXMLObject(qname);
    	attribute.setName("testAttribute");
    	XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory().getBuilder(XSString.TYPE_NAME);
    	XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
    	stringValue.setValue("attributeValue");
    	attribute.getAttributeValues().add(stringValue);
		return attribute;
	}

	@SuppressWarnings("rawtypes")
	public XMLObject buildXMLObject(QName objectQName){
        XMLObjectBuilder builder = Configuration.getBuilderFactory().getBuilder(objectQName);
        if(builder == null){
            throw new IllegalStateException("Unable to retrieve builder for object QName " + objectQName);
        }
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
    }
	
}
