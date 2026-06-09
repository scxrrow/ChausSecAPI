package com.chaussec.backend.models;
import lombok.Data;

@Data
public class SuricataAlertDTO {
    private String timestamp;
    private String sourceIp;
    private String destIp;
    private String alertSignature; // Ex: "ET SCAN Potential SSH Scan"
    private int severity;
}