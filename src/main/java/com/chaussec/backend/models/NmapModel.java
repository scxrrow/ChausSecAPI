package com.chaussec.backend.models;

import java.util.List;

public class NmapModel {

    private String target;
    private String status;
    private List<PortInfo> ports;
    private String os;
    private Timestamps timestamps;

    public String getTarget() { return target; }
    public void setTarget(String target) { this.target = target; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public List<PortInfo> getPorts() { return ports; }
    public void setPorts(List<PortInfo> ports) { this.ports = ports; }

    public String getOs() { return os; }
    public void setOs(String os) { this.os = os; }

    public Timestamps getTimestamps() { return timestamps; }
    public void setTimestamps(Timestamps timestamps) { this.timestamps = timestamps; }

    public static class PortInfo {
        private int port;
        private String state;
        private String service;

        public PortInfo() {}

        public PortInfo(int port, String state, String service) {
            this.port = port;
            this.state = state;
            this.service = service;
        }

        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }

        public String getState() { return state; }
        public void setState(String state) { this.state = state; }

        public String getService() { return service; }
        public void setService(String service) { this.service = service; }
    }

    public static class Timestamps {
        private String start;
        private String end;

        public Timestamps() {}

        public Timestamps(String start, String end) {
            this.start = start;
            this.end = end;
        }

        public String getStart() { return start; }
        public void setStart(String start) { this.start = start; }

        public String getEnd() { return end; }
        public void setEnd(String end) { this.end = end; }
    }
}
