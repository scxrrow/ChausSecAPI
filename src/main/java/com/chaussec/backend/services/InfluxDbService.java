package com.chaussec.backend.services;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.chaussec.backend.models.NmapModel;
import com.chaussec.backend.models.ScanMetricDTO;
import com.influxdb.client.InfluxDBClient;
import com.influxdb.client.QueryApi;
import com.influxdb.client.WriteApiBlocking;
import com.influxdb.client.domain.WritePrecision;
import com.influxdb.client.write.Point;
import com.influxdb.query.FluxRecord;
import com.influxdb.query.FluxTable;

@Service
public class InfluxDbService {

    @Autowired
    private InfluxDBClient influxDBClient;

    @Value("${influxdb.bucket}")
    private String bucket;

    @Value("${influxdb.org}")
    private String org;

    public void saveNmapMetrics(NmapModel result) {

        WriteApiBlocking writeApi = influxDBClient.getWriteApiBlocking();

        Point point = Point.measurement("nmap_scans")

                .addTag("target_ip", result.getTarget())
                .addTag("status", result.getStatus())

                .addField("open_ports_count", result.getOpenPorts() != null ? result.getOpenPorts().size() : 0)

                .time(Instant.now(), WritePrecision.NS);

        writeApi.writePoint(point);
        
        System.out.println("Métriques Nmap envoyées à InfluxDB pour l'IP : " + result.getTarget());
    }

    public List<ScanMetricDTO> getLast24hScans() {
        List<ScanMetricDTO> results = new ArrayList<>();
        QueryApi queryApi = influxDBClient.getQueryApi();

        String fluxQuery = String.format(
            "from(bucket:\"%s\") " +
            "|> range(start: -24h) " +
            "|> filter(fn: (r) => r._measurement == \"nmap_scans\")", 
            bucket 
        );

        List<FluxTable> tables = queryApi.query(fluxQuery, org);

        for (FluxTable fluxTable : tables) {
            for (FluxRecord fluxRecord : fluxTable.getRecords()) {
                ScanMetricDTO dto = new ScanMetricDTO();

                dto.setScanTime(fluxRecord.getTime());

                if (fluxRecord.getValueByKey("target_ip") != null) {
                    dto.setTargetIp(fluxRecord.getValueByKey("target_ip").toString());
                }
                if (fluxRecord.getValueByKey("status") != null) {
                    dto.setStatus(fluxRecord.getValueByKey("status").toString());
                }

                if ("open_ports_count".equals(fluxRecord.getField())) {
                    dto.setOpenPortsCount(((Long) fluxRecord.getValue()).intValue());
                }               
                results.add(dto);
            }
        }
        
        return results;
    }
}
