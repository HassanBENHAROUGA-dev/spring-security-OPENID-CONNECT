package com.sid.securityservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties(prefix = "rsa")/*Va dans le fichier configuration.properties et cherche toutes les propriétés qui commence par "rsa", récupere leurs valeurs et in jecte les dans les variables*/
public record RsakeysConfig(RSAPublicKey publicKey, RSAPrivateKey privateKey) {

}
