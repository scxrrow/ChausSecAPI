package com.chaussec.backend.controllers;


import com.chaussec.backend.services.LogSearchService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/chaussec/alerts")
public class SuricataAlertController {

        @Autowired
        private LogSearchService logSearchService;

        @GetMapping("/suricata")
        public ResponseEntity<String> getAlerts() {
            String alerts = logSearchService.getLatestSuricataAlerts();
            return ResponseEntity.ok(alerts);
        }
    }
}
