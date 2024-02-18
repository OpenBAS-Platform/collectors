package io.openbas.collectors.sentinel.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.openbas.collectors.sentinel.domain.Incident;
import io.openbas.collectors.sentinel.domain.ListOfIncidents;
import io.openbas.collectors.sentinel.infrastructure.SentinelRestApiCaller;
import io.openbas.collectors.sentinel.infrastructure.config.IncidentJsonDeserializer;
import io.openbas.collectors.sentinel.infrastructure.config.ResourceType;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Optional;

@Service
@Slf4j
public class SentinelService {

    private final SentinelRestApiCaller sentinelRestApiCaller;

    private final ObjectMapper mapper;

    public SentinelService(SentinelRestApiCaller sentinelRestApiCaller) {
        this.sentinelRestApiCaller = sentinelRestApiCaller;

        SimpleModule module = new SimpleModule();
        module.addDeserializer(ListOfIncidents.class, new IncidentJsonDeserializer());
        mapper = new ObjectMapper();
        mapper.registerModule(module);
    }

    public void fetchDataFromSentinelRestApi() {
        try {
            String incidentData = sentinelRestApiCaller.get(ResourceType.INCIDENTS, Strings.EMPTY, Optional.empty());
            ListOfIncidents listOfIncidents = mapper.readValue(incidentData, ListOfIncidents.class);
            log.info("Number of incidents: " + listOfIncidents.getIncidents().size());

            listOfIncidents.getIncidents().forEach(this::processIncident);
        } catch (IOException e) {
            log.error("Error fetching data from Sentinel REST API", e);
        }
    }

    private void processIncident(Incident incident) {
        try {
            log.info("Entities: " + sentinelRestApiCaller.post(ResourceType.INCIDENTS, incident.getSentinelId(), Optional.of(ResourceType.ENTITIES)));
            log.info("Alerts: " + sentinelRestApiCaller.post(ResourceType.INCIDENTS, incident.getSentinelId(), Optional.of(ResourceType.ALERTS)));
        } catch (Exception e) {
            log.error("Error processing incident: " + incident.getSentinelId(), e);
        }
    }
}
