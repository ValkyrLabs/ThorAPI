package com.valkyrlabs.thorapi.config.impl;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * <p>ValkyrAIAuthenticationSuccessHandler class.</p>
 *
 * @author johnmcmahon
 */
public class ValkyrAIAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  /** Constant <code>logger</code> */
  protected static final Logger logger = LoggerFactory.getLogger(ValkyrAIAuthenticationSuccessHandler.class);

  JwtToken tokenProvider;

  /**
   * <p>Constructor for ValkyrAIAuthenticationSuccessHandler.</p>
   *
   * @param token a {@link com.valkyrlabs.valkyrai.jwt.JwtToken} object
   */
  public ValkyrAIAuthenticationSuccessHandler(JwtToken token) {
    this.tokenProvider = token;
    logger.warn("ValkyrAIAuthenticationSuccessHandler instantiated with JwtToken: {}", tokenProvider != null);
  }

  /** {@inheritDoc} */
  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    // TODO: test the request username vs the jwt
    response.getWriter().println("ValkyrAIAuthenticationSuccessHandler: Authentication Success");
  }

}
