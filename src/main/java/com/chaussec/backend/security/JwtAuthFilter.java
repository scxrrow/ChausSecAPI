package com.chaussec.backend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    
    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

    @Autowired
    private JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);
        try {
            if (jwtService.isTokenValid(jwt) && SecurityContextHolder.getContext().getAuthentication() == null) {
                String username = jwtService.extractUsername(jwt);
                List<SimpleGrantedAuthority> authorities = jwtService.extractRoles(jwt);
                
                log.debug("JWT authentication successful for user: {} with roles: {}", username, authorities);

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        username, null, authorities
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            } else {
                log.warn("JWT validation failed or authentication already exists for token: {}", jwt.substring(0, Math.min(20, jwt.length())) + "...");
            }
        } catch (Exception e) {
            log.error("JWT authentication error: {} - {}", e.getClass().getSimpleName(), e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}