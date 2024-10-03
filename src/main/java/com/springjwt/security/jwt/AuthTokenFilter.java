package com.springjwt.security.jwt;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.springjwt.security.services.UserDetailsServiceImpl;

//The AuthTokenFilter class is a custom security filter that extends Spring's
//OncePerRequestFilter. It is part of a JWT-based authentication system, which intercepts HTTP
//requests and checks for a valid JSON Web Token (JWT) in the request headers. If a valid token is
//present, it authenticates the user by setting the authentication details in the Spring Security
//context. Here’s a breakdown of what the class does:
public class AuthTokenFilter extends OncePerRequestFilter {
  @Autowired
  private JwtUtils jwtUtils;

  //Extends OncePerRequestFilter: This ensures that the filter is applied only once per request,
  //even in scenarios with multiple filters.

  //JwtUtils: This utility class helps in extracting and validating JWTs.
  //UserDetailsServiceImpl: A custom service that loads user details (such as username and
  //authorities) from a database or another source.

  @Autowired
  private UserDetailsServiceImpl userDetailsService;

  private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    //The doFilterInternal method is the core logic where the filter processes the request.
    //Parameters:
    //HttpServletRequest: Represents the incoming HTTP request.
    //HttpServletResponse: Represents the HTTP response.
    //FilterChain: Allows passing the request and response to the next filter in the chain if
    //the current one does not block it.
    //The method is called for every incoming request, and this is where the JWT authentication
    //check occurs.
    try {
      logger.info(("Before Parsing"));
      String jwt = parseJwt(request);
      logger.info(("After Parsing -" + jwt));
      if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
        logger.info(("Inside If "));
        String username = jwtUtils.getUserNameFromJwtToken(jwt);
        logger.info(("Inside If Username is " + username));
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        logger.info(("Inside If userDetails is " + userDetails));

        //parseJwt(request): A helper function that extracts the JWT from the Authorization
        //header.
        //jwtUtils.validateJwtToken(jwt): Validates the extracted JWT. This checks whether the token
        //is valid, unexpired, and correctly signed.
        UsernamePasswordAuthenticationToken authentication =
            new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities());
        logger.info(("Inside If authentication is " + authentication));

        //Extract Username: Retrieves the username from the valid JWT.
        //Load UserDetails: Loads the user's details using userDetailsService, typically
        //fetching from a database or another service.
        //Create Authentication Object: A UsernamePasswordAuthenticationToken is created
        //using the user's details. This token is used by Spring Security to authenticate the
        //request.

        //Set Authentication Details: authentication.setDetails() sets additional information from
        //the request, like IP address, session info, etc.

        //Set Authentication in Context: The authenticated user is placed in the
        //SecurityContextHolder, making the user authenticated for the current session.

        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        logger.info(("Inside If authentication -Details are " + authentication.getDetails()));

        //If any exception occurs during the process (such as JWT validation failure), it is
        //logged, but the request processing continues.
        //After attempting to authenticate the request, the filter passes the request and
        //response along the filter chain, allowing other filters or the target resource to
        //process the request.

        SecurityContextHolder.getContext().setAuthentication(authentication);
      }
    } catch (Exception e) {
      logger.error("Cannot set user authentication: {}", e);
    }

    filterChain.doFilter(request, response);
  }

  private String parseJwt(HttpServletRequest request) {
    logger.info("Inside ParseJWT Function - Start");
    String headerAuth = request.getHeader("Authorization");

    if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
      logger.info("Inside ParseJWT Function - End " + headerAuth.substring(7));
      return headerAuth.substring(7);
    }

    return null;
  }
}

//Extract JWT from Header: This method checks the Authorization header for a JWT. It expects the
//header to start with the Bearer prefix, which is standard for JWTs in HTTP requests.

//If the Authorization header is properly formatted, it extracts the JWT by removing the
//"Bearer " prefix and returns the token. If the header is missing or incorrectly formatted,
//it returns null.

//Summary
//The AuthTokenFilter is a custom filter that:
//
//Intercepts incoming HTTP requests.
//Extracts and validates the JWT from the Authorization header.
//Authenticates the user by loading user details if the JWT is valid.
//Sets the authenticated user in Spring's security context.
//Continues the request processing by passing it to the next filter in the chain.
//In short, this filter ensures that only users with valid JWT tokens can access protected
// resources, and it automatically authenticates them based on the token.
