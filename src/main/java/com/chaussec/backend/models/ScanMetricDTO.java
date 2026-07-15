package com.chaussec.backend.models;

import lombok.Data;

@Data
public class ScanMetricDTO {
    private String id;
    private String target;
    private String status;
    private String startTime;
    private String endTime;
    private Integer portCount;
}
