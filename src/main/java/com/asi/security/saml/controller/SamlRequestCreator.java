package com.asi.security.saml.controller;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;

public class SamlRequestCreator {

    private static final String providerName = "www.advisorsoftware.com"; 
    
    @SuppressWarnings("rawtypes")
	public BasicSAMLMessageContext encodeSamlRequestMessage(SamlRequestData requestData)	throws Exception {
		AuthnRequest samlMessage = createResponse(requestData.getAcsURL());
		Endpoint samlEndpoint = createEndPoint(requestData.getIdProvider());
		BasicSAMLMessageContext messageContext = createMessageContext(samlMessage, samlEndpoint, requestData.getRelayState());
		return messageContext;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private BasicSAMLMessageContext createMessageContext(
			AuthnRequest samlMessage,
			Endpoint samlEndpoint, String relayState) {
        BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
        messageContext.setPeerEntityEndpoint(samlEndpoint);
        messageContext.setOutboundSAMLMessage(samlMessage);
        messageContext.setRelayState(relayState);
		return messageContext;
	}

	@SuppressWarnings("unchecked")
	private Endpoint createEndPoint(String idProvider) {
        SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) Configuration.getBuilderFactory()
                .getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        Endpoint samlEndpoint = endpointBuilder.buildObject();
        samlEndpoint.setLocation(idProvider);
		return samlEndpoint;
	}

	@SuppressWarnings("unchecked")
	private AuthnRequest createResponse(String acsURL) {
		
        SAMLObjectBuilder<AuthnRequest> requestBuilder = (SAMLObjectBuilder<AuthnRequest>) Configuration.getBuilderFactory()
                .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest samlMessage = requestBuilder.buildObject();
        samlMessage.setID("ASI");
        samlMessage.setVersion(SAMLVersion.VERSION_20);
        samlMessage.setIssueInstant(new DateTime());
        samlMessage.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        samlMessage.setProviderName(providerName);
        samlMessage.setIsPassive(false);
        samlMessage.setAssertionConsumerServiceURL(acsURL);	
        samlMessage.setIssuer(createIssuer());
        samlMessage.setNameIDPolicy(createNameIdPolicy());
		return samlMessage;
	}
	
	private Issuer createIssuer() {
        QName qname = new QName(SAMLConstants.SAML20_NS, Issuer.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);
        Issuer issuer = (Issuer) buildXMLObject(qname);
		issuer.setValue(providerName);
		return issuer;
	}
	
	private NameIDPolicy createNameIdPolicy(){
		QName nameIDPolicyQName = new QName(SAMLConstants.SAML20P_NS, NameIDPolicy.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20P_PREFIX);
        NameIDPolicy nameIdPolicy = (NameIDPolicy) buildXMLObject(nameIDPolicyQName);
        nameIdPolicy.setAllowCreate(false);
        nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
        return nameIdPolicy;
  	}
	
    private XMLObject buildXMLObject(QName objectQName){
        XMLObjectBuilder builder = Configuration.getBuilderFactory().getBuilder(objectQName);
        if(builder == null){
            throw new IllegalStateException("Unable to retrieve builder for object QName " + objectQName);
        }
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
    }

}
