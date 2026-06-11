package com.chaussec.backend.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
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

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Utile pour tester avec Postman au début
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/chaussec/nmap/**").hasRole("ADMIN") // Seul l'admin lance les scans
                .requestMatchers("/chaussec/api/stats/**").hasAnyRole("ADMIN", "USER") // Lecture pour tous
                .anyRequest().authenticated()
            )
            .httpBasic(Customizer.withDefaults()); // Utilise l'authentification basique HTTP pour l'instant

        return http.build();
    }

    // ==========================================
    // 2. LE SUPER-ADMIN (En Mémoire locale)
    // ==========================================
    @Bean
    public UserDetailsService inMemoryUserDetailsManager() {
        UserDetails superAdmin = User.builder()
            .username("superadmin")
            .password(passwordEncoder().encode("ChausSecAdmin2026!"))
            .roles("ADMIN")
            .build();
        
        return new InMemoryUserDetailsManager(superAdmin);
    }

    // ==========================================
    // 3. LES UTILISATEURS LDAP (Le reste de l'équipe)
    // ==========================================
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

    // ==========================================
    // 4. L'ENCODEUR DE MOT DE PASSE
    // ==========================================
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}