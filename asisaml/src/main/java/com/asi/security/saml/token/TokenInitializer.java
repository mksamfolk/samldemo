package com.asi.security.saml.token;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.persistence.EntityManagerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.asi.compassdb.helper.EntityManagerFactoryKeeper;

@Component("tokenInitializer")
public class TokenInitializer {

	@Autowired
	public TokenInitializer(
			@Value("${ENCRYPT_KEY}") final String encryptionKey,
			@Value("${API_CORE_URL}") final String apiCoreUrl,
			@Value("${API_SESSION_URL}") final String apiSessionUrl
			) throws Exception {
		
		EncryptorFactory.setEncryptKey(encryptionKey);
		
		// This can turn to a properties file
		
		Properties dbProp = new Properties();
		dbProp.load(TokenInitializer.class.getClassLoader().getResourceAsStream("db_config.properties"));
		
		Map<String,String> coreProps = new HashMap<>();
		Map<String,String> sessionProps = new HashMap<>();
		
        Set<Object> keys = dbProp.keySet();
        for(Object  k : keys){
            String key = (String)k;
            if (key.startsWith("core.hibernate")) {
            	coreProps.put(key.substring("core.".length()), dbProp.getProperty(key));
            } else if (key.startsWith("session.hibernate")) {
            	sessionProps.put(key.substring("session.".length()), dbProp.getProperty(key));
            }
        }
		
        coreProps.put("hibernate.connection.url", apiCoreUrl);
		EntityManagerFactory coreEMF = javax.persistence.Persistence.createEntityManagerFactory(dbProp.getProperty("core.persistence.name"), coreProps);
		EntityManagerFactoryKeeper.setCoreEMF(coreEMF);
		
        sessionProps.put("hibernate.connection.url", apiSessionUrl);
	    EntityManagerFactory sessionEMF = javax.persistence.Persistence.createEntityManagerFactory(dbProp.getProperty("session.persistence.name"), sessionProps);
	    EntityManagerFactoryKeeper.setSessionEMF(sessionEMF);
	    
	}
	
}
