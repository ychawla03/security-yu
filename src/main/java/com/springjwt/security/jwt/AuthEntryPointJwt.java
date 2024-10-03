package com.springjwt.security.jwt;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

//The AuthEntryPointJwt class is a custom authentication entry
//point in a Spring Boot application. It is used to handle unauthorized access to protected
//resources, specifically in the context of a REST API that uses JSON Web Tokens (JWT) for
//authentication. Let me break it down:

//@Component: This annotation makes this class a Spring-managed bean, so it can be automatically
//detected and instantiated by Spring.
//implements AuthenticationEntryPoint: The class implements the AuthenticationEntryPoint
//interface, which is part of Spring Security. This interface is used to handle what happens
//when a user tries to access a protected resource without being authenticated.

//The commence method is invoked whenever an unauthorized request is made to a secured endpoint.
//        Parameters:
//        HttpServletRequest: Represents the incoming HTTP request.
//        HttpServletResponse: Represents the HTTP response.
//        AuthenticationException: The exception that occurs when authentication fails.

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

  private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
      throws IOException, ServletException {

    //Logs the error message when unauthorized access occurs, including the reason from authException.
    logger.error("Unauthorized error: {}", authException.getMessage());

    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

    //setContentType: Sets the response type to JSON (application/json), meaning the response
    //will be sent as a JSON object.
    //setStatus: Sets the HTTP status code to 401 (SC_UNAUTHORIZED) to indicate that the request
    //was unauthorized.
    final Map<String, Object> body = new HashMap<>();
    body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
    body.put("error", "Unauthorized");
    body.put("message", authException.getMessage());
    body.put("path", request.getServletPath());

    //This creates a Map<String, Object> that will represent the body of the JSON response. The
    //map contains:
    //status: The HTTP status code (401).
    //error: A brief message ("Unauthorized").
    //message: The actual exception message explaining why the request was unauthorized.
    //path: The URI path of the request, helping the client understand where the issue
    //occurred.
    final ObjectMapper mapper = new ObjectMapper();
    mapper.writeValue(response.getOutputStream(), body);
  }

  //ObjectMapper: This is from the Jackson library and is used to convert the body map into
  //JSON format.
  //writeValue: Writes the JSON response to the HTTP response output stream.

  // Summary
  //The AuthEntryPointJwt class is a custom handler for unauthorized access attempts in a Spring
  //Security-based application. When an unauthorized user (e.g., someone without a valid JWT)
  //tries to access a protected resource, this class:
  //
  //Logs the unauthorized access attempt.
  //Responds with a 401 Unauthorized status.
  //Returns a JSON response containing details such as the status code, error message, the
  //reason for the failure, and the path of the request.
  //This allows a REST API to return structured error messages in JSON format to clients
  //(like a frontend or another service) whenever an authentication failure occurs.
}
