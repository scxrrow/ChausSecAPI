package com.chaussec.backend.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class LogSearchService {

    // L'URL de ton OpenSearch ou Graylog (à mettre dans application.properties)
    @Value("${opensearch.url}")
    private String searchEngineUrl; 

    public String getLatestSuricataAlerts() {
        RestTemplate restTemplate = new RestTemplate();
        
        // 1. On construit la requête pour OpenSearch/Elasticsearch
        // Exemple : Chercher les logs où "event_type" est "alert"
        String queryUrl = searchEngineUrl + "/suricata-logs/_search?q=event_type:alert&size=50&sort=@timestamp:desc";

        try {
            // 2. On interroge la base de données de logs
            ResponseEntity<String> response = restTemplate.getForEntity(queryUrl, String.class);
            
            // 3. On renvoie le JSON brut (ou on le transforme en SuricataAlertDTO)
            return response.getBody();
            
        } catch (Exception e) {
            return "{\"error\": \"Impossible de contacter le moteur de recherche\"}";
        }
    }
}
