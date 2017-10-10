package com.asi.security.saml.controller;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;

public class AssertionFinder {

	public static Assertion findAssertion(Response samlResponse) throws Exception {
		if ( samlResponse.getAssertions().size() > 0 )
			return samlResponse.getAssertions().get(0);
		else
			return null;
	}
}
