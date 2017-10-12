package com.asi.security.saml.token;

import java.util.HashMap;

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
			) {
		
		EncryptorFactory.setEncryptKey(encryptionKey);
		
		// This can turn to a properties file
		
		HashMap<String, String> coreConfig = new HashMap<>();
	      coreConfig.put("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
	      coreConfig.put("hibernate.connection.driver_class", "org.postgresql.Driver");
	      coreConfig.put("hibernate.connection.url", apiCoreUrl);
	      coreConfig.put("hibernate.default_schema", "core");
	      coreConfig.put("hibernate.ejb.naming_strategy", "org.hibernate.cfg.ImprovedNamingStrategy");
	      coreConfig.put("hibernate.connection.autoReconnect", "true");
	      coreConfig.put("hibernate.cache.use_second_level_cache", "false");
	      coreConfig.put("hibernate.temp.use_jdbc_metadata_defaults", "false");
	      coreConfig.put("hibernate.c3p0.min_size", "3");
	      coreConfig.put("hibernate.c3p0.max_size", "30");
	      coreConfig.put("hibernate.c3p0.maxIdleTimeExcessConnections", "120");
	      coreConfig.put("hibernate.c3p0.max_statements", "50");
	      coreConfig.put("hibernate.c3p0.idle_test_period", "900");
	      coreConfig.put("hibernate.c3p0.preferredTestQuery", "SELECT 1");
	      coreConfig.put("hibernate.show_sql", "false");  
	      coreConfig.put("hibernate.jdbc.time_zone", "UTC");
		
		EntityManagerFactory coreEMF = javax.persistence.Persistence.createEntityManagerFactory("asi-compass-data", coreConfig);
		
		EntityManagerFactoryKeeper.setCoreEMF(coreEMF);
		
		HashMap<String, String> sessionConfig = new HashMap<>();
		sessionConfig.put("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
		sessionConfig.put("hibernate.connection.driver_class", "org.postgresql.Driver");
		sessionConfig.put("hibernate.connection.url", apiSessionUrl);
		sessionConfig.put("hibernate.default_schema", "session");
		sessionConfig.put("hibernate.ejb.naming_strategy", "org.hibernate.cfg.ImprovedNamingStrategy");
		sessionConfig.put("hibernate.connection.autoReconnect", "true");
		sessionConfig.put("hibernate.cache.use_second_level_cache", "false");
		sessionConfig.put("hibernate.temp.use_jdbc_metadata_defaults", "false");
	    sessionConfig.put("hibernate.c3p0.min_size", "3");
	    sessionConfig.put("hibernate.c3p0.max_size", "30");
	    sessionConfig.put("hibernate.c3p0.maxIdleTimeExcessConnections", "120");
	    sessionConfig.put("hibernate.c3p0.max_statements", "50");
	    sessionConfig.put("hibernate.c3p0.idle_test_period", "900");
	    sessionConfig.put("hibernate.c3p0.preferredTestQuery", "SELECT 1");
	    sessionConfig.put("hibernate.show_sql", "false");  
	    sessionConfig.put("hibernate.jdbc.time_zone", "UTC");
		
	    EntityManagerFactory sessionEMF = javax.persistence.Persistence.createEntityManagerFactory("asi-session-data", sessionConfig);
	    
	    EntityManagerFactoryKeeper.setSessionEMF(sessionEMF);
	    
	}
	
	
}
