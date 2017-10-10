package com.asi.security.saml.controller;

import java.security.KeyException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.commons.httpclient.NameValuePair;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
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
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.stereotype.Service;

@Service
public class SamlServices {
	
	private VelocityEngine velocityEngine;
	
	private XMLObjectBuilderFactory builderFactory;
	
	public SamlServices() throws Exception {
		DefaultBootstrap.bootstrap();
		
		builderFactory = Configuration.getBuilderFactory();
		
        velocityEngine = new VelocityEngine();
        velocityEngine.setProperty(RuntimeConstants.ENCODING_DEFAULT, "UTF-8");
        velocityEngine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
        velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
        velocityEngine.setProperty("classpath.resource.loader.class",
                "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        velocityEngine.init();
	}
	

	public void createSamlRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
		
		HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);
		
        QName qname = new QName(SAMLConstants.SAML20_NS, Issuer.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
        Issuer issuer = (Issuer) buildXMLObject(qname);
        issuer.setValue("ASI");
		
		// Build message
		SAMLObjectBuilder<AuthnRequest> responseBuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
		AuthnRequest samlMessage = responseBuilder.buildObject();
		samlMessage.setID("foo");
		samlMessage.setIssuer(issuer);
		samlMessage.setVersion(SAMLVersion.VERSION_20);
		samlMessage.setIssueInstant(new DateTime(0));
		samlMessage.setAssertionConsumerServiceURL("http://localhost:8080/saml/callback");
		 
		// Build end point
		SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		Endpoint samlEndpoint = endpointBuilder.buildObject();
		samlEndpoint.setLocation("http://localhost:8080/saml/idp");
		 
		// Build message context
		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setPeerEntityEndpoint(samlEndpoint);
		messageContext.setOutboundSAMLMessage(samlMessage);
		messageContext.setRelayState("relay");
		         
		// create HTML form post
		HTTPPostEncoder encoder = new HTTPPostEncoder(velocityEngine, "/templates/saml2-post-binding.vm");
		encoder.encode(messageContext);
		
	}
	
	
    private XMLObject buildXMLObject(QName objectQName){
        XMLObjectBuilder builder = builderFactory.getBuilder(objectQName);
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
    }
	
	public void receiveSamlRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
		
		// find ACS URL, Relay state, issuer Id
		BasicSAMLMessageContext requestMessageContext = new BasicSAMLMessageContext();
		requestMessageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
		HTTPPostDecoder decoder = new HTTPPostDecoder();
		decoder.decode(requestMessageContext);
		AuthnRequest samlRequest = (AuthnRequest)requestMessageContext.getInboundSAMLMessage();
		String acsURL = samlRequest.getAssertionConsumerServiceURL();
		String relayState = requestMessageContext.getRelayState();
		String spId = samlRequest.getIssuer().getValue();

		
		HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);
		 
		// Build success status code
		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		StatusCode statusCode = statusCodeBuilder.buildObject();
		statusCode.setValue(StatusCode.SUCCESS_URI);
		 
		// Build status
		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Status responseStatus = statusBuilder.buildObject();
		responseStatus.setStatusCode(statusCode);
		
		// build assertion
		Assertion assertion = createAssertion(acsURL, "someone", "TESTER");
		signAssertion(assertion, "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCPfc64IF+p/wvEkBVmS+CR+6lLQZoPEC/oxOGeLV7zTP9QgRU36SLb/iT9zWBxxx70Vu4K9b65szoxotRKTJHt8OtFsRf4XjhXAkJ0leWrcDB2P7nN8Lbg37j1+xXilRiXCdQ/htD1456jHYl1wqDSU2r6hB14GyzbAMZ/uD1Npjfuc6sK3OxFuTJilh0W9MzmBHdR17eaFjvu7XKQziJAoUq9ufD0DSi2F3gH8FRl+qmSxgztOzSTZJrlkGvHnfiuqRkJXF1mI0loOLsL0G0/4JEQ2fDlqt9QHq6mSRdl1dkrTb3CvHPm6s+NI+VHUB8Cq3N+OuZohZq+OzyitUmFAgMBAAECggEAIzsVdVnlgxyu6/0gc/RvWAh9QZAC3m3wBWvJpYeoR36BNWfsKMUiHPeiZ3p0kpr8O6vYWHKL+JZL1IIRM4jnT4+WhI79vqqLlLlmTa+8K0Kpc28kFK9kh4QGqsaSUgafef4c0dgtGCJiAdSvum0mBV4b5xRnE+VANylSk2tOCfFFh7+1XZ9MF1jFlYcX7dSIopnALtVvUc0IflMEeXH9HMLoL+FqwnNUaXQ7biuI4zRmztdl+bbCmpj0hAwnyQARuKOVINvYWixNLq26bGoP7DL+8uvLQva9amgM0idpFWHcjP0ADeBDRVLQsBmhmcqtCBV1QjGkkpDp6zAh419gBQKBgQDgE0xTBFg86ZQayaXsKhPqE34LXsuI2HFNdxRPtvnmF9zJ2zNpTiiO9r/YpozoXHH8bFCYQt/y/IjrrGh7NF2HH66JAi6pcKqrvN6dOyMtaIIQQEv/kJp+me9WIeB5CPEinwTxy3Q5vWviSRdg/VP63qNE5gqbYmfwI78sI26c6wKBgQCj717yHqiMsuLAJ2m/mmFZE126hGcqrgnC5vfQGSApiH6ta0IXxkBif0Owlo77Oh3wcZB5FiXLkRsdKHC6evnjqouMuk3eX5PEjXGMr7BIYWrUqLyulG55/VMrngkDucYm50MZt7wHvEqhzu8SsDcOkj7LPr82QjbcADmkGP1XTwKBgHUDnuf7bNjiYaVbiHo7vwqOA1SMvF1KKmD5vnGia/3smDAReFeVqTh/QtAwqYTuQdg/+BaLVcfeeOIZtrYgMndN5CdILHXvkDD/AIG7UDN2T/WMniNnsEZMvN+N8VtDgClEQaDDTn6YnK4e3UaZBDIN8dUZDJD4Yq7U/BBgsHLhAoGAUzT8DAhjpIZncQCQPCAvqPabbEAn3RHZAoQY5BbcrDgLlBoMweRuaZAO22KP0BP/fjsmCU+kf153VKViEkS48UVu707gly4L4oeoSrAh2ZsYjjfXDQVpzaE2xbzA9pMkcDqRZExNs99uQhK2ZdXrHAo+tQp0IyYYkjHLD+9fJyECgYAlE3gmHPuh2hsSVFuhRfc6QsOuaFSEYntZXa+xw9/zKscB6MSnZrkOfysdW5Q5SmvG/6Z1MiuKVT3QayEEJcKU7Nqe0BZb04RdW4sZ7ik7GKijVBxS8dHDwb256kY0zGmaUnrb+mPVlcew2CCmk7yO13Hu7WbPewxnhW+KxnDYFA==");
		
		// Build response
		SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
		Response samlMessage = responseBuilder.buildObject();
		samlMessage.setID("foo");
		samlMessage.setVersion(SAMLVersion.VERSION_20);
		samlMessage.setIssueInstant(new DateTime(0));
		samlMessage.setStatus(responseStatus);
		samlMessage.getAssertions().add(assertion);
		
		// Build end point
		SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		Endpoint samlEndpoint = endpointBuilder.buildObject();
		samlEndpoint.setLocation(acsURL);
		 
		
		// Build message context
		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setPeerEntityEndpoint(samlEndpoint);
		messageContext.setOutboundSAMLMessage(samlMessage);
		messageContext.setRelayState(relayState);
		
		// create HTML form post
		HTTPPostEncoder encoder = new HTTPPostEncoder(velocityEngine, "/templates/saml2-post-binding.vm");
		encoder.encode(messageContext);

	}
	
	private void signAssertion(Assertion assertion, String privateKey) throws Exception {
		RSAPrivateKey signingPrivateKey = SecurityHelper.buildJavaRSAPrivateKey(privateKey);
		
	    BasicX509Credential credential = new BasicX509Credential();
	    credential.setUsageType(UsageType.SIGNING);
	    credential.setPrivateKey(signingPrivateKey);
	    
	    Signature signature = (Signature) Configuration.getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		
		assertion.setSignature(signature);
		
	    Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
	    Signer.signObject(signature);
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

	

	
	public void receiveSamlResponse(HttpServletRequest request, HttpServletResponse response)
	throws Exception {
		
		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
		HTTPPostDecoder decoder = new HTTPPostDecoder();
		decoder.decode(messageContext);
		
		Response samlResponse = (Response)messageContext.getInboundSAMLMessage();
		Assertion assertion = samlResponse.getAssertions().get(0);
		String idp = assertion.getIssuer().getValue();
		String subjectId = assertion.getSubject().getNameID().getValue();
		boolean status = isResponseStatusSccess(samlResponse);
		Collection<NameValuePair> attributes = retrieveAttributes(assertion);
		
		System.out.println("Issuer: " + idp);
		System.out.println("SubjectId: " + subjectId);
		System.out.println("status: " + status);
		System.out.println("number of attributes: " + attributes.size());
		for (NameValuePair nvp : attributes) {
			System.out.println(" " + nvp.getName() + " : " + nvp.getValue());
		}
		
		if (verifySignature(messageContext, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj33OuCBfqf8LxJAVZkvgkfupS0GaDxAv6MThni1e80z/UIEVN+ki2/4k/c1gccce9FbuCvW+ubM6MaLUSkyR7fDrRbEX+F44VwJCdJXlq3Awdj+5zfC24N+49fsV4pUYlwnUP4bQ9eOeox2JdcKg0lNq+oQdeBss2wDGf7g9TaY37nOrCtzsRbkyYpYdFvTM5gR3Ude3mhY77u1ykM4iQKFKvbnw9A0othd4B/BUZfqpksYM7Ts0k2Sa5ZBrx534rqkZCVxdZiNJaDi7C9BtP+CRENnw5arfUB6upkkXZdXZK029wrxz5urPjSPlR1AfAqtzfjrmaIWavjs8orVJhQIDAQAB")) {
			response.getWriter().write("done");
		} else {
			response.getWriter().write("bad");
		}
		
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
