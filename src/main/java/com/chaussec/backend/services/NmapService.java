package com.chaussec.backend.services;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.chaussec.backend.models.NmapModel;

@Service
public class NmapService {

    private static final Pattern SAFE_TARGET = Pattern.compile(
        "^(\\d{1,3}\\.){3}\\d{1,3}(/\\d{1,2})?$|^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}$"
    );

    @Autowired
    private InfluxDbService influxDbService;

    public NmapModel executeScan(String target) throws IOException {
        if (target == null || !SAFE_TARGET.matcher(target).matches()) {
            throw new IllegalArgumentException("Cible invalide : " + target);
        }
        // Commande : nmap -sV -oX - (le "-" envoie le XML dans la console)
        ProcessBuilder pb = new ProcessBuilder("nmap", "-sV", "-oX", "-", target);
        Process process = pb.start();

        // On lit le résultat (flux de sortie)
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line);
        }

        // Création de l'objet résultat
        NmapModel result = new NmapModel();
        result.setTarget(target);
        result.setRawOutput(output.toString()); // On stocke le XML brut
        result.setStatus("Success");
        influxDbService.saveNmapMetrics(result);
        // Note : Ici, il faudrait ajouter un parser XML pour remplir 'openPorts'
        return result;
    }
}
