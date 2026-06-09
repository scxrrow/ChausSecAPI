package com.chaussec.backend.config;

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
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // ==========================================
    // 1. LES RÈGLES D'ACCÈS (Qui peut faire quoi)
    // ==========================================
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
        // A. Connexion au serveur LDAP (à adapter selon votre Docker Compose)
        DefaultSpringSecurityContextSource contextSource = 
            new DefaultSpringSecurityContextSource("ldap://localhost:389/dc=chaussec,dc=org");
        contextSource.setUserDn("cn=admin,dc=chaussec,dc=org"); // Compte pour lire le LDAP
        contextSource.setPassword("adminpassword");
        contextSource.afterPropertiesSet();

        // B. Comment trouver l'utilisateur qui essaie de se connecter
        // Ici, on cherche dans l'unité d'organisation (ou) "people" par son "uid"
        FilterBasedLdapUserSearch userSearch = 
            new FilterBasedLdapUserSearch("ou=people", "(uid={0})", contextSource);

        BindAuthenticator authenticator = new BindAuthenticator(contextSource);
        authenticator.setUserSearch(userSearch);

        // C. Récupération des rôles (Groupes LDAP)
        DefaultLdapAuthoritiesPopulator authoritiesPopulator = 
            new DefaultLdapAuthoritiesPopulator(contextSource, "ou=groups");
        authoritiesPopulator.setGroupRoleAttribute("cn"); // Le nom du groupe devient le rôle

        return new LdapAuthenticationProvider(authenticator, authoritiesPopulator);
    }

    // ==========================================
    // 4. L'ENCODEUR DE MOT DE PASSE
    // ==========================================
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}