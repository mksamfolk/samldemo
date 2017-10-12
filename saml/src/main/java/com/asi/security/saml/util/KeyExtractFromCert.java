package com.asi.security.saml.util;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

/*
 * 
   pom.xml

<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.asi</groupId>
  <artifactId>keytest</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <dependencies>
  	<dependency>
  		<groupId>org.bouncycastle</groupId>
  		<artifactId>bcpg-jdk16</artifactId>
  		<version>1.46</version>
  	</dependency>
  	<dependency>
  		<groupId>org.bouncycastle</groupId>
  		<artifactId>bcprov-jdk16</artifactId>
  		<version>1.46</version>
  	</dependency>
	<dependency>
	    <groupId>org.bouncycastle</groupId>
	    <artifactId>bcprov-ext-jdk16</artifactId>
	    <version>1.46</version>
	</dependency>
  </dependencies>
</project>

*/

/*
 * Create keystore
 * C:\Temp>c:\tools\Java\jdk1.8.0_131\bin\keytool.exe -keyalg RSA -genkey -keystore .\myKeyStore.jks -storepass password -alias samlTestKey -dname "CN=ASI, OU=ASI, O=ASI, L=ASI, S=CA, C=US"
 * 
 * Export certificate
 * C:\Temp>c:\tools\Java\jdk1.8.0_131\bin\keytool.exe -export -alias samlTestKey -file samlTestKey.cer -keystore myKeyStore.jks
 * 
 */

public class KeyExtractFromCert 
{

	public static void main(String[] args) throws Exception {
		
		// certificate
		Certificate certificate = readCertificateFromFile(new File("C:/temp/samlTestKey.cer"));
		
		// public key from certificate
		System.out.println("retrieve public key from certificate");
		String publicKeyFromCert = readPublicKeyFromCert(certificate);
		verifyPublicKey(publicKeyFromCert);
        System.out.println(publicKeyFromCert);
        
        // key store
        KeyStore keystore = readKeyStoreFromJks(new File("C:/temp/myKeyStore.jks"), "password");
        
        // public key from key store
		System.out.println("retrieve public key from keystore");
		String publicKeyFromStore = readPublicKeyFromCert(readCertificateFromStore(keystore, "samlTestKey"));
		verifyPublicKey(publicKeyFromStore);
        System.out.println(publicKeyFromStore);
        
        // private key from key store
		System.out.println("retrieve private key from keystore");
		String privateKeyFromStore = readPrivateKeyFromKeystore(keystore, "samlTestKey", "password");
		verifyPrivateKey(privateKeyFromStore);
        System.out.println(privateKeyFromStore);
        
        
        PublicKey publicKey = createPublicKey(publicKeyFromCert);
        PrivateKey privateKey = createPrivateKey(privateKeyFromStore);
        
        String encrypted = encrpytMessage("foo and bar", publicKey);
        String decrypted = decryptMessage(encrypted, privateKey);
        
        System.out.println("encrypted: " + encrypted);
        System.out.println("decrypted: " + decrypted);
        
	}

	// extract public key from cert
	private static String readPublicKeyFromCert(Certificate certificate) throws Exception {
		PublicKey publicKey = certificate.getPublicKey();
		String encodedPublic = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		return encodedPublic;
	}

	// read cert from text file
	private static Certificate readCertificateFromFile(File certificateFile) throws Exception {
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		Certificate certificate = f.generateCertificate(new FileInputStream(certificateFile));
		return certificate;
	}
	
	// read cert from keystore jks
	private static Certificate readCertificateFromStore(KeyStore keystore, String alias) throws Exception {
		Certificate certificate = keystore.getCertificate(alias);
		return certificate;
	}
	
	// read keystore from jks
	private static KeyStore readKeyStoreFromJks(File jks, String password) throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(jks), "password".toCharArray());
        return keystore;
	}
	
	// read private key from store
	private static String readPrivateKeyFromKeystore(KeyStore keystore, String alias, String password) throws Exception {
		Key key = keystore.getKey(alias, password.toCharArray());
		String encodedPrivate = Base64.getEncoder().encodeToString(key.getEncoded());
		return encodedPrivate;
	}
	

	private static PrivateKey verifyPrivateKey(String privateKeyContent) throws Exception {
		PrivateKey privateKey = createPrivateKey(privateKeyContent);
		System.out.println(privateKey.getAlgorithm());
		return privateKey;
	}


	private static PrivateKey createPrivateKey(String privateKeyContent) throws Exception {
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent.getBytes()));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(spec);
		return privateKey;
	}
	
	private static PublicKey verifyPublicKey(String publicKeyContent) throws Exception {
		PublicKey publicKey = createPublicKey(publicKeyContent);
		System.out.println(publicKey.getAlgorithm());
		return publicKey;
	}


	private static PublicKey createPublicKey(String publicKeyContent) throws Exception {
		X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent.getBytes()));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(spec);
		return publicKey;
	}
    
	private static String encrpytMessage(String message, PublicKey publicKey) throws Exception {
		
		// Get a cipher object.
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	 
		// Gets the raw bytes to encrypt, UTF8 is needed for
		// having a standard character set
		byte[] stringBytes = message.getBytes("UTF8");
	 
		// encrypt using the cypher
		byte[] raw = cipher.doFinal(stringBytes);
	 
		// converts to base64 for easier display.
		String base64 = new String(Base64.getEncoder().encode(raw));
	 
		return base64;
	}
	
	private static String  decryptMessage(String message, PrivateKey privateKey) throws Exception {
		// Get a cipher object.
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		 
		//decode the BASE64 coded message
		byte[] raw = Base64.getDecoder().decode(message);
	 
		//decode the message
		byte[] stringBytes = cipher.doFinal(raw);
	 
		//converts the decoded message to a String
		String clear = new String(stringBytes, "UTF8");
		return clear;
	}
}