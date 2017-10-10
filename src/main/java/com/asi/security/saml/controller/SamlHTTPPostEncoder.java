package com.asi.security.saml.controller;

import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.ConfigurationException;

public class SamlHTTPPostEncoder 
{

	private VelocityEngine velocityEngine;
	
	public SamlHTTPPostEncoder() throws Exception {
		velocityEngine = initVelocityAndOthers();
	}
	
	private VelocityEngine initVelocityAndOthers() throws ConfigurationException, Exception {
		VelocityEngine velocityEngine = new VelocityEngine();
		
		velocityEngine.setProperty( RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS,
			      "org.apache.velocity.runtime.log.Log4JLogChute" );
		velocityEngine.setProperty("runtime.log.logsystem.log4j.logger",
				SamlHTTPPostEncoder.class.getName());

        velocityEngine.setProperty(RuntimeConstants.ENCODING_DEFAULT, "UTF-8");
        velocityEngine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
        velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
        velocityEngine.setProperty("classpath.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        velocityEngine.init();
		return velocityEngine;
	}
	
	@SuppressWarnings("rawtypes")
	public void encode(BasicSAMLMessageContext messageContext, HttpServletResponse response) throws Exception {
		HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);
		messageContext.setOutboundMessageTransport(outTransport);
		HTTPPostEncoder encoder = new HTTPPostEncoder(velocityEngine, "/templates/saml2-post-binding.vm");
		encoder.encode(messageContext);
	}
	
}