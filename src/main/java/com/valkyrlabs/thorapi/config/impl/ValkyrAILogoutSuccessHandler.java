package com.valkyrlabs.thorapi.config.impl;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * <p>ValkyrAILogoutSuccessHandler class.</p>
 *
 * @author johnmcmahon
 */
public class ValkyrAILogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    /** {@inheritDoc} */
    @Override
    public void onLogoutSuccess(final HttpServletRequest request, final HttpServletResponse response,
            final Authentication authentication) throws IOException, ServletException {
        response.sendRedirect("/");
        super.onLogoutSuccess(request, response, authentication);

    }

}
