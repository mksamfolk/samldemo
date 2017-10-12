package com.asi.security.saml.token;

import java.net.URL;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;

public class RelayStateInterpreter {
	
	private Map<String, String> queryPairs = new LinkedHashMap<String, String>();
	
	private SessionInfo sessionInfo;
	
	private URL relayURL;
	
	public SessionInfo readRelayState(String relayState) throws Exception {
		
		SessionIdInterpreter ssInterpreter = new SessionIdInterpreter();
		
		relayURL = new URL(relayState);
		String query = relayURL.getQuery();
		
	    String[] pairs = query.split("&");
	    for (String pair : pairs) {
	        int idx = pair.indexOf("=");
	        queryPairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
	    }
		
		String p = queryPairs.get("p");
		sessionInfo = ssInterpreter.readAuthToken(p);
		
		return sessionInfo;
	}

	public Map<String, String> getQueryPairs() {
		return queryPairs;
	}

	public SessionInfo getSessionInfo() {
		return sessionInfo;
	}

	public URL getRelayURL() {
		return relayURL;
	}
	
}
