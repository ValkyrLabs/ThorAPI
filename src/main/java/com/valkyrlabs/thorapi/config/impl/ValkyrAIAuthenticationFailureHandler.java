package com.valkyrlabs.thorapi.config.impl;

import java.io.IOException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * <p>ValkyrAIAuthenticationFailureHandler class.</p>
 *
 * @author johnmcmahon
 */
public class ValkyrAIAuthenticationFailureHandler implements AuthenticationFailureHandler {

  /** {@inheritDoc} */
  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException exception) throws IOException, ServletException {
    response.getWriter().println("ValkyrAIAuthenticationFailureHandler: Authentication FAILURE");
  }

}
