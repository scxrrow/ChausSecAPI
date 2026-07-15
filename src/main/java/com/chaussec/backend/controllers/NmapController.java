package com.chaussec.backend.controllers;
import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.chaussec.backend.models.NmapModel;
import com.chaussec.backend.models.ScanMetricDTO;
import com.chaussec.backend.services.InfluxDbService;
import com.chaussec.backend.services.NmapService;

@RestController
@RequestMapping("/chaussec/nmap") 
public class NmapController {

    @Autowired 
    private NmapService nmapService;

    @Autowired
    private InfluxDbService influxService;

    @PostMapping("/scan")
    public ResponseEntity<NmapModel> startScan(@RequestParam String target) {
        try {
            NmapModel result = nmapService.executeScan(target);
            return ResponseEntity.ok(result);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(400).build();
        } catch (IOException e) {
            return ResponseEntity.status(500).build();
        }
    }

    @GetMapping("/scans")
    public ResponseEntity<List<ScanMetricDTO>> getScanHistory() {
        try {
            List<ScanMetricDTO> history = influxService.getLast24hScans();
            return ResponseEntity.ok(history);
        } catch (Exception e) {
            return ResponseEntity.status(500).build();
        }
    }
}
