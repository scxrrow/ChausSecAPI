package com.chaussec.backend.models;

import java.time.Instant;

import lombok.Data;

@Data
public class ScanMetricDTO {
    private String targetIp;
    private String status;
    private Integer openPortsCount;
    private Instant scanTime;
}
