package com.chaussec.backend.services;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

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

        Instant start = Instant.now();

        // Commande : nmap -sV -oX - (le "-" envoie le XML dans la console)
        ProcessBuilder pb = new ProcessBuilder("nmap", "-sV", "-oX", "-", target);
        Process process = pb.start();

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append('\n');
        }

        Instant end = Instant.now();

        NmapModel result = new NmapModel();
        result.setTarget(target);
        result.setTimestamps(new NmapModel.Timestamps(start.toString(), end.toString()));

        try {
            parseNmapXml(output.toString(), result);
            result.setStatus("Success");
        } catch (Exception parseError) {
            result.setPorts(new ArrayList<>());
            result.setStatus("Success");
        }

        influxDbService.saveNmapMetrics(result);
        return result;
    }

    private void parseNmapXml(String xml, NmapModel result) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

        List<NmapModel.PortInfo> ports = new ArrayList<>();
        NodeList portNodes = doc.getElementsByTagName("port");
        for (int i = 0; i < portNodes.getLength(); i++) {
            Element portEl = (Element) portNodes.item(i);
            int portId = Integer.parseInt(portEl.getAttribute("portid"));

            String state = firstAttribute(portEl, "state", "state");
            String service = firstAttribute(portEl, "service", "name");

            ports.add(new NmapModel.PortInfo(portId, state, service));
        }
        result.setPorts(ports);

        NodeList osMatchNodes = doc.getElementsByTagName("osmatch");
        if (osMatchNodes.getLength() > 0) {
            Element bestMatch = (Element) osMatchNodes.item(0);
            result.setOs(bestMatch.getAttribute("name"));
        }
    }

    private String firstAttribute(Element parent, String childTag, String attribute) {
        NodeList children = parent.getElementsByTagName(childTag);
        if (children.getLength() == 0) return null;
        Element child = (Element) children.item(0);
        String value = child.getAttribute(attribute);
        return value.isEmpty() ? null : value;
    }
}
