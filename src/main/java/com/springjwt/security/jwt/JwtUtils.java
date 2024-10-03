package com.springjwt.security.jwt;

import java.security.Key;
import java.util.Date;

import com.springjwt.security.services.UserDetailsImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

//The JwtUtils class is a utility class for managing JSON Web Tokens (JWTs) in a Spring Boot
//application. It handles generating, validating, and parsing JWTs, which are used for securing
//communication between the server and clients (typically in RESTful APIs). Here's a detailed
//breakdown of the class:
@Component
public class JwtUtils {

  //@Component: This makes the class a Spring-managed bean, meaning it can be autowired into
  //other classes.
  //Logger: The logger logs various actions for debugging and monitoring purposes.
  //@Value Annotations: These annotations inject values from the application properties:
  //jwtSecret: The secret key used to sign the JWT.
  //jwtExpirationMs: The JWT expiration time in milliseconds.
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  @Value("${abcCookie-jwt}")
  private String jwtSecret;

  @Value("${app.jwtExpirationMs}")
  private int jwtExpirationMs;

  public String generateJwtToken(Authentication authentication) {

    UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
    logger.info(userPrincipal.getUsername() + " " + userPrincipal.getPassword());

    //Authentication object: The method takes an Authentication object as input, representing the
    //logged-in user's details.

    //userPrincipal: This is an instance of UserDetailsImpl, which holds user details like username
    //and password. The username will be used as the token's subject.

    //JWT Generation:
    //setSubject(): The token's subject is set to the username of the authenticated user.
    //setIssuedAt(): The token is issued at the current date and time.
    //setExpiration(): The expiration time is set based on the configured jwtExpirationMs.
    //signWith(): The token is signed using the secret key (jwtSecret) and the HS256 signature
    //algorithm.
    //compact(): The method builds and returns the JWT as a string.

    return Jwts.builder()
        .setSubject(userPrincipal.getUsername())
        .setIssuedAt(new Date())
            .setExpiration(new Date(new Date().getTime() + jwtExpirationMs))
        .signWith(key(), SignatureAlgorithm.HS256)
        .compact();
  }

  //This method returns a Key object derived from the jwtSecret.
  //Base64 Decoding: The secret key (jwtSecret) is expected to be Base64-encoded, so it is decoded
  //before being used to generate the signing key.
  //hmacShaKeyFor(): This method from the Keys utility class is used to create the key based on
  //the decoded secret.
  //The key is logged for debugging purposes.

  //This method extracts the username from a given JWT.
  //parseClaimsJws(): The method parses the JWT string, verifying the signature with the secret
  //key. It returns the claims (the payload of the JWT).
  //getSubject(): This retrieves the subject (username) from the claims.
  private Key key() {

    logger.info("jwtSecret is " + jwtSecret);
    logger.info("Base64 Key is " + Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret)));
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
  }

  public String getUserNameFromJwtToken(String token) {
    return Jwts.parserBuilder().setSigningKey(key()).build()
               .parseClaimsJws(token).getBody().getSubject();
  }

  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    //validateJwtToken(): This method validates the JWT by trying to parse it.

    //Key Operations:
    //It attempts to parse the JWT using the secret key.
    //If parsing is successful, the token is valid, and true is returned.

    //Exception Handling:
    //MalformedJwtException: The token is not well-formed.
    //ExpiredJwtException: The token has expired.
    //UnsupportedJwtException: The token uses an unsupported format or algorithm.
    //IllegalArgumentException: The token's claims are empty or invalid.
    //If any of these exceptions are caught, the error is logged, and the method returns false.
    return false;
  }

  //Summary
  //The JwtUtils class provides utility methods to:
  //
  //Generate a JWT: It creates a token that includes the authenticated user's username as the
  //subject and signs it using a secret key (jwtSecret).
  //Extract Information: It can extract the username from a JWT by parsing its claims.
  //Validate JWT: It checks whether the token is valid by ensuring it's correctly signed, not
  //expired, and well-formed.
  //This utility is crucial in a JWT-based authentication system, helping to secure API endpoints
  //by issuing, parsing, and verifying JWTs.
}
