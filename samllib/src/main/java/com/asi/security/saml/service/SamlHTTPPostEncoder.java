package com.asi.security.saml.service;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.springframework.stereotype.Component;

@Component
public class SamlHTTPPostEncoder {
	
	private VelocityEngine velocityEngine;
	private HTTPPostEncoder httpPostRequestEncoder;
	private HTTPPostEncoder httpPostResposneEncoder;
	
	public SamlHTTPPostEncoder() throws Exception {
		DefaultBootstrap.bootstrap();
        velocityEngine = new VelocityEngine();
        velocityEngine.setProperty(RuntimeConstants.ENCODING_DEFAULT, "UTF-8");
        velocityEngine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
        velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
        velocityEngine.setProperty("classpath.resource.loader.class",
                "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        velocityEngine.init();
        
        httpPostRequestEncoder = new HTTPPostEncoder(velocityEngine, "/templates/saml2-post-binding.vm");
        httpPostResposneEncoder = new HTTPPostEncoder(velocityEngine, "/templates/saml2-post-binding.vm");
	}
	
	public void encodeRequest(BasicSAMLMessageContext messageContext) throws Exception {
		httpPostRequestEncoder.encode(messageContext);
	}

	public void encodeResponse(BasicSAMLMessageContext messageContext) throws Exception {
		httpPostResposneEncoder.encode(messageContext);
	}

}
