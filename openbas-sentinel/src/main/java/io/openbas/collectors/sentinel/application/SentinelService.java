package io.openbas.collectors.sentinel.application;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.openbas.collectors.sentinel.domain.ListOfIncidents;
import io.openbas.collectors.sentinel.infrastructure.SentinelRestApiCaller;
import io.openbas.collectors.sentinel.infrastructure.config.IncidentJsonDeserializer;
import io.openbas.collectors.sentinel.infrastructure.config.ResourceType;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.stereotype.Service;

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

    public void fetchingDataFromSentinelRestApi() throws JsonProcessingException {
        //Retrieve incidents
        String incident0 = sentinelRestApiCaller.get(ResourceType.INCIDENTS, Strings.EMPTY, Optional.empty());
        ListOfIncidents listOfIncidents = mapper.readValue(incident0, ListOfIncidents.class);
        log.info("Number of incidents : " + listOfIncidents.getIncidents().size());

        //Get entities and alerts from an incidente !! https://learn.microsoft.com/fr-fr/rest/api/securityinsights/incidents/list-entities?view=rest-securityinsights-2023-11-01&tabs=HTTP#filehashentity
        listOfIncidents.getIncidents().forEach(incident -> {
            log.info("entities : " + sentinelRestApiCaller.post(ResourceType.INCIDENTS, incident.getSentinelId(), Optional.of(ResourceType.ENTITIES)));
            log.info("alerts : " + sentinelRestApiCaller.post(ResourceType.INCIDENTS, incident.getSentinelId(), Optional.of(ResourceType.ALERTS)));
        });
    }
}
