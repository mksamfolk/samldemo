package com.asi.security.saml.service;

import java.security.interfaces.RSAPrivateKey;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
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
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.springframework.stereotype.Component;

import com.asi.security.saml.model.SamlResponseData;

@Component
public class SamlResponseEncoder {

	private SamlObjectBuilder samlObjectBuilder;
	
	public SamlResponseEncoder(SamlObjectBuilder samlObjectBuilder) {
		this.samlObjectBuilder = samlObjectBuilder;
	}
	
	public BasicSAMLMessageContext encodeHTTPPostSamlResponse(
			HttpServletRequest request, HttpServletResponse response,
			SamlResponseData responseData) throws Exception {
		
		// find ACS URL, Relay state, issuer Id
		BasicSAMLMessageContext requestMessageContext = samlObjectBuilder.buildMessageContext();
		requestMessageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
		HTTPPostDecoder decoder = new HTTPPostDecoder();
		decoder.decode(requestMessageContext);
		
		
		AuthnRequest samlRequest = (AuthnRequest)requestMessageContext.getInboundSAMLMessage();
		String acsURL = samlRequest.getAssertionConsumerServiceURL();
		String relayState = requestMessageContext.getRelayState();
		String spId = samlRequest.getIssuer().getValue();

		
		HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);
		 
		// Build success status code
		StatusCode statusCode = samlObjectBuilder.buildStatusCode();
		statusCode.setValue(StatusCode.SUCCESS_URI);
		 
		// Build status
		Status responseStatus = samlObjectBuilder.buildStatus();
		responseStatus.setStatusCode(statusCode);
		
		// build assertion
		Assertion assertion = createAssertion(acsURL, responseData.getSubjectId(), responseData.getIssuerId());
		signAssertion(assertion, "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCPfc64IF+p/wvEkBVmS+CR+6lLQZoPEC/oxOGeLV7zTP9QgRU36SLb/iT9zWBxxx70Vu4K9b65szoxotRKTJHt8OtFsRf4XjhXAkJ0leWrcDB2P7nN8Lbg37j1+xXilRiXCdQ/htD1456jHYl1wqDSU2r6hB14GyzbAMZ/uD1Npjfuc6sK3OxFuTJilh0W9MzmBHdR17eaFjvu7XKQziJAoUq9ufD0DSi2F3gH8FRl+qmSxgztOzSTZJrlkGvHnfiuqRkJXF1mI0loOLsL0G0/4JEQ2fDlqt9QHq6mSRdl1dkrTb3CvHPm6s+NI+VHUB8Cq3N+OuZohZq+OzyitUmFAgMBAAECggEAIzsVdVnlgxyu6/0gc/RvWAh9QZAC3m3wBWvJpYeoR36BNWfsKMUiHPeiZ3p0kpr8O6vYWHKL+JZL1IIRM4jnT4+WhI79vqqLlLlmTa+8K0Kpc28kFK9kh4QGqsaSUgafef4c0dgtGCJiAdSvum0mBV4b5xRnE+VANylSk2tOCfFFh7+1XZ9MF1jFlYcX7dSIopnALtVvUc0IflMEeXH9HMLoL+FqwnNUaXQ7biuI4zRmztdl+bbCmpj0hAwnyQARuKOVINvYWixNLq26bGoP7DL+8uvLQva9amgM0idpFWHcjP0ADeBDRVLQsBmhmcqtCBV1QjGkkpDp6zAh419gBQKBgQDgE0xTBFg86ZQayaXsKhPqE34LXsuI2HFNdxRPtvnmF9zJ2zNpTiiO9r/YpozoXHH8bFCYQt/y/IjrrGh7NF2HH66JAi6pcKqrvN6dOyMtaIIQQEv/kJp+me9WIeB5CPEinwTxy3Q5vWviSRdg/VP63qNE5gqbYmfwI78sI26c6wKBgQCj717yHqiMsuLAJ2m/mmFZE126hGcqrgnC5vfQGSApiH6ta0IXxkBif0Owlo77Oh3wcZB5FiXLkRsdKHC6evnjqouMuk3eX5PEjXGMr7BIYWrUqLyulG55/VMrngkDucYm50MZt7wHvEqhzu8SsDcOkj7LPr82QjbcADmkGP1XTwKBgHUDnuf7bNjiYaVbiHo7vwqOA1SMvF1KKmD5vnGia/3smDAReFeVqTh/QtAwqYTuQdg/+BaLVcfeeOIZtrYgMndN5CdILHXvkDD/AIG7UDN2T/WMniNnsEZMvN+N8VtDgClEQaDDTn6YnK4e3UaZBDIN8dUZDJD4Yq7U/BBgsHLhAoGAUzT8DAhjpIZncQCQPCAvqPabbEAn3RHZAoQY5BbcrDgLlBoMweRuaZAO22KP0BP/fjsmCU+kf153VKViEkS48UVu707gly4L4oeoSrAh2ZsYjjfXDQVpzaE2xbzA9pMkcDqRZExNs99uQhK2ZdXrHAo+tQp0IyYYkjHLD+9fJyECgYAlE3gmHPuh2hsSVFuhRfc6QsOuaFSEYntZXa+xw9/zKscB6MSnZrkOfysdW5Q5SmvG/6Z1MiuKVT3QayEEJcKU7Nqe0BZb04RdW4sZ7ik7GKijVBxS8dHDwb256kY0zGmaUnrb+mPVlcew2CCmk7yO13Hu7WbPewxnhW+KxnDYFA==");
		
		// Build response
		Response samlMessage = samlObjectBuilder.buildResponse();
		samlMessage.setID("foo");
		samlMessage.setVersion(SAMLVersion.VERSION_20);
		samlMessage.setIssueInstant(new DateTime(0));
		samlMessage.setStatus(responseStatus);
		samlMessage.getAssertions().add(assertion);
		
		// Build end point
		Endpoint samlEndpoint = samlObjectBuilder.buildEndpoint();
		samlEndpoint.setLocation(acsURL);
		 
		
		// Build message context
		BasicSAMLMessageContext messageContext = samlObjectBuilder.buildMessageContext();
		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setPeerEntityEndpoint(samlEndpoint);
		messageContext.setOutboundSAMLMessage(samlMessage);
		messageContext.setRelayState(relayState);
		
		return messageContext;
		
	}
	
	
	private Assertion createAssertion(String acsURL, String subjectId, String issuerId) throws Exception {
		Issuer issuer = samlObjectBuilder.buildIssuer();
		issuer.setValue(issuerId);
        Assertion assertion = samlObjectBuilder.buildAssertion();
        assertion.setIssueInstant(new DateTime(0));
        assertion.setIssuer(issuer);
        assertion.getAuthnStatements().add(createAuthnStatement());
        assertion.getAttributeStatements().add(createUserIdAttributeStatement());
        assertion.setConditions(createConditions(acsURL));
        assertion.setSubject(createSubject(subjectId));
		return assertion;
	}
	
	private AuthnStatement createAuthnStatement() {
		AuthnStatement authnStatement = samlObjectBuilder.buildAuthnStatement();
		authnStatement.setAuthnInstant( new DateTime());
		authnStatement.setSessionNotOnOrAfter(new DateTime());
		authnStatement.setAuthnContext(createAuthnContext());
		return authnStatement;
	}
	
	private AttributeStatement createUserIdAttributeStatement() {
        AttributeStatement attributeStatement = samlObjectBuilder.buildAttributeStatement();
        attributeStatement.getAttributes().add(createAttribute("foo", "bar"));
		return attributeStatement;
	}
	
	private Conditions createConditions(String acsURL) {
        Conditions conditions = samlObjectBuilder.buildConditions();
        conditions.getAudienceRestrictions().add(createAudienceRestriction(acsURL));
		return conditions;
	}
	
	private Subject createSubject(String subjectId) {
        Subject subject = samlObjectBuilder.buildSubject();
        subject.setNameID(createNameID(subjectId));
		return subject;
	}
	
	private AuthnContext createAuthnContext() {
		AuthnContext authnContext = samlObjectBuilder.buildAuthnContext();
		authnContext.setAuthnContextClassRef(createAuthnContextClassRef());
		return authnContext;
	}
	
    private Attribute createAttribute(String name, String value) {
    	Attribute attribute = samlObjectBuilder.buildAttribute();
    	attribute.setName(name);
    	attribute.getAttributeValues().add(samlObjectBuilder.buildAttributeValue(value));
		return attribute;
	}
    
	private AudienceRestriction createAudienceRestriction(String acsURL) {
        AudienceRestriction audienceRestriction = samlObjectBuilder.buildAudienceRestriction();
        audienceRestriction.getAudiences().add(createAudience(acsURL));
		return audienceRestriction;
	}
	
	private NameID createNameID(String subjectId){
		NameID nameId = samlObjectBuilder.buildNameID();
		nameId.setValue(subjectId);
		return nameId;
	}
	
	private AuthnContextClassRef createAuthnContextClassRef() {
		AuthnContextClassRef classRef = samlObjectBuilder.buildAuthnContextClassRef();
		return classRef;
	}
	
	private Audience createAudience(String acsURL) {
        Audience audience = samlObjectBuilder.buildAudience();
        audience.setAudienceURI(acsURL);
		return audience;
	}

	private void signAssertion(Assertion assertion, String privateKey) throws Exception {
		RSAPrivateKey signingPrivateKey = SecurityHelper.buildJavaRSAPrivateKey(privateKey);
		
	    BasicX509Credential credential = new BasicX509Credential();
	    credential.setUsageType(UsageType.SIGNING);
	    credential.setPrivateKey(signingPrivateKey);
	    
	    Signature signature = samlObjectBuilder.buildSignature();
		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		
		assertion.setSignature(signature);
		
	    Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
	    Signer.signObject(signature);
	}
	
	
}
