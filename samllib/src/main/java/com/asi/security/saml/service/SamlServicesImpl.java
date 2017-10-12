package com.asi.security.saml.service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.asi.security.saml.api.SamlConfig;
import com.asi.security.saml.api.SamlServices;
import com.asi.security.saml.api.SingleSignOn;
import com.asi.security.saml.model.SamlAcsData;
import com.asi.security.saml.model.SamlRequestData;
import com.asi.security.saml.model.SamlResponseData;

@Service
public class SamlServicesImpl implements SamlServices {
	
	@Autowired
	private SamlConfig samlConfig;
	
	@Autowired
	private SamlHTTPPostEncoder samlHTTPPostEncoder;

	@Autowired
	private SamlRequestEncoder samlRequestEncoder;

	@Autowired
	private SamlResponseEncoder samlResponseEncoder;

	@Autowired
	private SamlAssertionConsumer samlAssertionConsumer;
	
	@Autowired
	private SingleSignOn singleSignOn;
	
	
	public void perform(String action, HttpServletRequest request, HttpServletResponse response) 
			throws Exception {
		
		if (action.equals(samlConfig.getSSOPath())) {
			createSamlRequest(request, response);
		} else if (action.equals(samlConfig.getACSPath())) {
			receiveSamlResponse(request, response);
		} else if (action.equals(samlConfig.getIDPPath())) {
			receiveSamlRequest(request, response);
		} else {
			response.getWriter().print("action not defined: " + action);
		}
		
	}

	/**
	 * Create and encode HTTP POST SAML request 
	 * 
	 * @param request
	 * @param response
	 * @throws Exception
	 */
	public void createSamlRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
		
		// setup request data
		SamlRequestData requestData = new SamlRequestData();
		requestData.setAcsURL(samlConfig.getAcsURL());
		requestData.setIdpURL(samlConfig.getIdpURL());
		requestData.setRelayState(request.getParameter(samlConfig.getBackParam()));
		
		samlHTTPPostEncoder.encodeRequest(samlRequestEncoder.encodeHTTPPostSamlRequest(request, response, requestData));
	}
	
	/**
	 * Receive and consume SAML Assertion.
	 * 
	 * @param request
	 * @param response
	 * @return
	 * @throws Exception
	 */
	public void receiveSamlResponse(HttpServletRequest request, HttpServletResponse response) throws Exception {
		SamlAcsData acsData = samlAssertionConsumer.consumeAssertion(request);
		singleSignOn.process(acsData.getSubjectId(), acsData.getRelayState(), response);
	}
	
	/**
	 * Provide demonstration of SAML ID Provider
	 * 
	 * @param request
	 * @param response
	 * @throws Exception
	 */
	public void receiveSamlRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
		SamlResponseData responseData = new SamlResponseData();
		responseData.setSubjectId("someone");
		samlHTTPPostEncoder.encodeResponse(samlResponseEncoder.encodeHTTPPostSamlResponse(request, response, responseData));
	}

}
