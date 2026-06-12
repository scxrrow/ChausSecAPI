package com.chaussec.backend.config;

import com.chaussec.backend.security.JwtAuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
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

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Correspond aux env vars docker-compose : LDAP_URL, LDAP_BASE_DN, LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD
    @Value("${ldap.url:ldap://localhost:389}")
    private String ldapUrl;

    @Value("${ldap.base-dn:dc=chaussec,dc=eu}")
    private String ldapBaseDn;

    @Value("${ldap.admin-dn:cn=admin,dc=chaussec,dc=eu}")
    private String ldapAdminDn;

    @Value("${ldap.admin-password:Chaussec2026!}")
    private String ldapAdminPassword;

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
    public AuthenticationManager authenticationManager() {
        // LDAP en premier, fallback sur superadmin in-memory
        DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider(inMemoryUserDetailsManager());
        daoProvider.setPasswordEncoder(passwordEncoder());

        try {
            LdapAuthenticationProvider ldapProvider = buildLdapProvider();
            return new ProviderManager(List.of(ldapProvider, daoProvider));
        } catch (Exception e) {
            // LDAP indisponible au démarrage → in-memory uniquement
            return new ProviderManager(List.of(daoProvider));
        }
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
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private LdapAuthenticationProvider buildLdapProvider() throws Exception {
        DefaultSpringSecurityContextSource contextSource =
                new DefaultSpringSecurityContextSource(ldapUrl + "/" + ldapBaseDn);
        contextSource.setUserDn(ldapAdminDn);
        contextSource.setPassword(ldapAdminPassword);
        contextSource.afterPropertiesSet();

        BindAuthenticator authenticator = new BindAuthenticator(contextSource);
        authenticator.setUserDnPatterns(new String[]{"uid={0},ou=users", "cn={0},ou=users"});

        DefaultLdapAuthoritiesPopulator authorities =
                new DefaultLdapAuthoritiesPopulator(contextSource, "ou=groups");
        authorities.setGroupRoleAttribute("cn");

        return new LdapAuthenticationProvider(authenticator, authorities);
    }
}
