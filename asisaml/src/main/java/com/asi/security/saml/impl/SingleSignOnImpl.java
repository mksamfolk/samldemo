package com.asi.security.saml.impl;

import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.DependsOn;
import org.springframework.stereotype.Component;

import com.asi.compassdb.dao.session.ASISessionManager;
import com.asi.compassdb.entity.session.ASISession;
import com.asi.compassdb.helper.EntityManagerFactoryKeeper;
import com.asi.security.saml.api.SingleSignOn;
import com.asi.security.saml.token.SessionIdInterpreter;
import com.asi.security.saml.token.SessionInfo;

@Component
@DependsOn("tokenInitializer")
public class SingleSignOnImpl implements SingleSignOn {
	
	public void process(String subject, String relayState, HttpServletResponse response) throws Exception {
		
		EntityManager sessionEM = EntityManagerFactoryKeeper.getSessionEMF().createEntityManager();
		
		SessionIdInterpreter ssInterpreter = new SessionIdInterpreter();
		
		URL relayURL = new URL(relayState);
		Map<String, String> queryPairs = new LinkedHashMap<String, String>();
		String query = relayURL.getQuery();
		
	    String[] pairs = query.split("&");
	    for (String pair : pairs) {
	        int idx = pair.indexOf("=");
	        queryPairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
	    }
		
		String p = queryPairs.get("p");
		SessionInfo sessionInfo = ssInterpreter.readAuthToken(p);
		
		sessionEM.getTransaction().begin();
		try {
			ASISession newSession = ASISessionManager.createNewSession(sessionEM, sessionInfo.getTenantName(), subject, null, null);
			String sessionId = newSession.getSessionId();
			queryPairs.put("p", sessionId);
			sessionEM.getTransaction().commit();
		} catch(Exception ex) {
			sessionEM.getTransaction().rollback();
		} finally {
			sessionEM.close();
		}

		StringBuilder newQuery = new StringBuilder();
		for (Map.Entry<String, String> e : queryPairs.entrySet()) {
			if (newQuery.length() != 0) {
				newQuery.append("&");
			}
			newQuery.append(e.getKey()).append("=").append(URLEncoder.encode(e.getValue(),"UTF-8"));
		}
		
		String newLocation = relayURL.toExternalForm().replaceFirst("\\?.*$", "") + "?" + newQuery.toString();
		response.sendRedirect(newLocation);
		
	}

}
