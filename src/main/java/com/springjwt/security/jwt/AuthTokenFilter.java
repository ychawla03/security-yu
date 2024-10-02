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

public class AuthTokenFilter extends OncePerRequestFilter {
  @Autowired
  private JwtUtils jwtUtils;

  @Autowired
  private UserDetailsServiceImpl userDetailsService;

  private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
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
        UsernamePasswordAuthenticationToken authentication =
            new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities());
        logger.info(("Inside If authentication is " + authentication));
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        logger.info(("Inside If authentication -Details are " + authentication.getDetails()));
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
