package com.chaussec.backend.models;

import java.util.List;

public class NmapModel {

    private String target;
    private String status;
    private List<String> openPorts;
    private String rawOutput;

    public String getTarget() { return target; }
    public void setTarget(String target) { this.target = target; }

    public String getRawOutput() { return rawOutput; }
    public void setRawOutput(String rawOutput) { this.rawOutput = rawOutput; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public List<String> getOpenPorts() { return openPorts; }
    public void setOpenPorts(List<String> openPorts) { this.openPorts = openPorts; }
}
