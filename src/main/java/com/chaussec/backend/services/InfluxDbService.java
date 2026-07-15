package com.chaussec.backend.services;

import java.time.Duration;
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

        Instant start = Instant.parse(result.getTimestamps().getStart());
        Instant end = Instant.parse(result.getTimestamps().getEnd());
        long durationMs = Duration.between(start, end).toMillis();
        int portCount = result.getPorts() != null ? result.getPorts().size() : 0;

        Point point = Point.measurement("nmap_scans")
                .addTag("target_ip", result.getTarget())
                .addTag("status", result.getStatus())
                .addField("open_ports_count", portCount)
                .addField("duration_ms", durationMs)
                .time(start, WritePrecision.NS);

        writeApi.writePoint(point);

        System.out.println("Métriques Nmap envoyées à InfluxDB pour l'IP : " + result.getTarget());
    }

    public List<ScanMetricDTO> getLast24hScans() {
        List<ScanMetricDTO> results = new ArrayList<>();
        QueryApi queryApi = influxDBClient.getQueryApi();

        String fluxQuery = String.format(
            "from(bucket:\"%s\") " +
            "|> range(start: -24h) " +
            "|> filter(fn: (r) => r._measurement == \"nmap_scans\") " +
            "|> pivot(rowKey: [\"_time\"], columnKey: [\"_field\"], valueColumn: \"_value\")",
            bucket
        );

        List<FluxTable> tables = queryApi.query(fluxQuery, org);

        for (FluxTable fluxTable : tables) {
            for (FluxRecord fluxRecord : fluxTable.getRecords()) {
                ScanMetricDTO dto = new ScanMetricDTO();

                Instant startTime = fluxRecord.getTime();
                dto.setStartTime(startTime != null ? startTime.toString() : null);

                Object targetIp = fluxRecord.getValueByKey("target_ip");
                dto.setTarget(targetIp != null ? targetIp.toString() : null);

                Object status = fluxRecord.getValueByKey("status");
                dto.setStatus(status != null ? status.toString() : null);

                Object openPortsCount = fluxRecord.getValueByKey("open_ports_count");
                int portCount = openPortsCount != null ? ((Number) openPortsCount).intValue() : 0;
                dto.setPortCount(portCount);

                Object durationMsValue = fluxRecord.getValueByKey("duration_ms");
                if (startTime != null && durationMsValue != null) {
                    long durationMs = ((Number) durationMsValue).longValue();
                    dto.setEndTime(startTime.plusMillis(durationMs).toString());
                }

                dto.setId((startTime != null ? startTime.toEpochMilli() : 0) + "-" + dto.getTarget());

                results.add(dto);
            }
        }

        return results;
    }
}
