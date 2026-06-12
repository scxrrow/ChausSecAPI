package com.chaussec.backend.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.chaussec.backend.security.JwtAuthFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.ldap.urls}")
    private String ldapUrls;

    @Value("${spring.ldap.base}")
    private String ldapBaseDn;

    @Value("${spring.ldap.username}")
    private String ldapUsername;

    @Value("${spring.ldap.password}")
    private String ldapPassword;

    @Autowired
    private JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())

            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/chaussec/cki/**").permitAll()
                .requestMatchers("/chaussec/nmap/**").hasRole("ADMIN")
                .requestMatchers("/chaussec/alerts/**").hasRole("ADMIN")
                .requestMatchers("/chaussec/requin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )

            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public UserDetailsService inMemoryUserDetailsManager() {
        UserDetails superAdmin = User.builder()
            .username("superadmin")
            .password(passwordEncoder().encode("ChausSecAdmin2026!"))
            .roles("ADMIN")
            .build();
        
        return new InMemoryUserDetailsManager(superAdmin);
    }


    @Bean
    public LdapAuthenticationProvider ldapAuthenticationProvider() {
        // On remplace les chaînes de caractères par nos variables
        DefaultSpringSecurityContextSource contextSource = 
            new DefaultSpringSecurityContextSource(ldapUrls + "/" + ldapBaseDn);
        
        contextSource.setUserDn(ldapUsername); 
        contextSource.setPassword(ldapPassword);
        contextSource.afterPropertiesSet();

        BindAuthenticator authenticator = new BindAuthenticator(contextSource);
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=users", "cn={0},ou=users"});

        DefaultLdapAuthoritiesPopulator authorities = 
            new DefaultLdapAuthoritiesPopulator(contextSource, "ou=groups");
        authorities.setGroupRoleAttribute("cn"); 

        return new LdapAuthenticationProvider(authenticator, authorities);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}