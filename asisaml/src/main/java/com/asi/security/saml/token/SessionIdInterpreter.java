package com.asi.security.saml.token;

import javax.persistence.EntityManager;

import com.asi.compassdb.dao.session.ASISessionManager;
import com.asi.compassdb.dao.tenant.TenantDao;
import com.asi.compassdb.entity.session.ASISession;
import com.asi.compassdb.entity.tenant.Tenant;
import com.asi.compassdb.helper.EntityManagerFactoryKeeper;

public class SessionIdInterpreter {
	
	private static final int SESSION_LENGTH = 32;
	
	public SessionInfo readAuthToken(String authToken) throws IllegalAccessException {
		
		SessionInfo ssInfo = new SessionInfo();
		
		if (authToken == null || "null".equals(authToken)) {
			throw new IllegalAccessException();
		}
		
		// for non session based token
		if (authToken.length() > SESSION_LENGTH) {
			ssInfo.nonSessionToken = true;
			String encryptedClientSecret = authToken;
			try {
				ClientSecretEncryptor decryptor = new ClientSecretEncryptor();
				decryptor.setEncryptedClientSecret(encryptedClientSecret);
				decryptor.decrypt(EncryptorFactory.createEncryptor());
				ssInfo.clientId = decryptor.getClientId();
				ssInfo.clientSecret = decryptor.getClientSecret();
				
				if (null != decryptor.getAdvisorPermalinkId()) {
					ssInfo.advisorPermalinkId = decryptor.getAdvisorPermalinkId();
				}
			} catch(Exception e) {
				throw new IllegalAccessException();
			}
			ssInfo.tenantName = threeScaleCheck(ssInfo.clientId, ssInfo.clientSecret);
		} else {
			ASISession session = ASISessionManager.readSession(authToken);
			if (session == null) {
				throw new IllegalStateException();
			}
			if (session.getTotpRequired() != null && session.getTotpRequired()) {
				ssInfo.totpRequired = true;
			}
			if (session.getResetPwdRequired() != null && session.getResetPwdRequired()) {
				ssInfo.resetPwdRequired = true;
			}
			
			try {
				ssInfo.encryptedClientSecret = session.getOrgUnit();
				if (ssInfo.encryptedClientSecret != null) {
					ClientSecretEncryptor decryptor = new ClientSecretEncryptor();
					decryptor.setEncryptedClientSecret(ssInfo.encryptedClientSecret);
					decryptor.decrypt(EncryptorFactory.createEncryptor());
					ssInfo.clientId = decryptor.getClientId();
					ssInfo.clientSecret = decryptor.getClientSecret();
				}
			} catch (Exception e) {
				throw new IllegalAccessException();
			}
			
			ssInfo.sessionId = session.getSessionId();
			ssInfo.tenantName = session.getTenantId();
			ssInfo.username = session.getUserId();
			ssInfo.tokenType = session.getUserAccountNumber();
			ssInfo.advisorPermalinkId = session.getAdvisorPermalinkId();
		}
		
		return ssInfo;
	}
	
	private String threeScaleCheck(String clientId, String clientSecret) throws IllegalAccessException {
		EntityManager coreEM = EntityManagerFactoryKeeper.getCoreEMF().createEntityManager();
		try {
			Tenant tenant = TenantDao.getTenantByClientId(coreEM, clientId);
			String tenantName = tenant.getName();
			return tenantName;
		} catch(Exception ex) {
			throw new IllegalAccessException();
		} finally {
			coreEM.close();
		}
	}
}
