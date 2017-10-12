package com.asi.security.saml.impl;

import java.net.URLEncoder;
import java.util.Map;

import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.DependsOn;
import org.springframework.stereotype.Component;

import com.asi.compassdb.dao.session.ASISessionManager;
import com.asi.compassdb.entity.session.ASISession;
import com.asi.compassdb.helper.EntityManagerFactoryKeeper;
import com.asi.security.saml.api.SingleSignOn;
import com.asi.security.saml.token.RelayStateInterpreter;
import com.asi.security.saml.token.SessionInfo;

@Component
@DependsOn("tokenInitializer")
public class SingleSignOnImpl implements SingleSignOn {
	
	public void process(String subject, String relayState, HttpServletResponse response) throws Exception {
		
		RelayStateInterpreter rsInterpreter = new RelayStateInterpreter();
		rsInterpreter.readRelayState(relayState);
		
		Map<String, String> queryPairs = rsInterpreter.getQueryPairs();
		SessionInfo sessionInfo = rsInterpreter.getSessionInfo();
		
		EntityManager sessionEM = EntityManagerFactoryKeeper.getSessionEMF().createEntityManager();
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
		
		String newLocation = rsInterpreter.getRelayURL().toExternalForm().replaceFirst("\\?.*$", "") + "?" + newQuery.toString();
		response.sendRedirect(newLocation);
		
	}

}
