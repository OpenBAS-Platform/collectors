package io.openbas.collectors.sentinel.application;

import io.openbas.collectors.sentinel.infrastructure.SentinelRestApiCaller;
import io.openbas.collectors.sentinel.infrastructure.config.ResourceType;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
public class SentinelService {

    private final SentinelRestApiCaller sentinelRestApiCaller;

    public SentinelService(SentinelRestApiCaller sentinelRestApiCaller) {
        this.sentinelRestApiCaller = sentinelRestApiCaller;
    }

    public void fetchingDataFromSentinelRestApi() {
        //Retrieve alerts
        /*String alerts = sentinelRestApiCaller.get(ResourceType.ALERT_RULES, Strings.EMPTY, Optional.empty());
        log.info(alerts);*/

        //Retrieve actions from alert rules
        /*String actionsAlerts = sentinelRestApiCaller.get(ResourceType.ALERT_RULES, "BuiltInFusion", Optional.of(ResourceType.ACTIONS));
        log.info("actions : " + actionsAlerts);*/

        //Retrieve incidents
        String incidents = sentinelRestApiCaller.get(ResourceType.INCIDENTS, Strings.EMPTY, Optional.empty());
        log.info("incidents : " + incidents);

        //Retrieve SecurityAlerts from incidents
        /*String incident0a = sentinelRestApiCaller.get(ResourceType.INCIDENTS, "57e35aff-e61f-4f3b-b15d-2138743f365e", Optional.of(ResourceType.RELATIONS));
        log.info("relations : " + incident0a);*/

        /*String incident0b = sentinelRestApiCaller.post(ResourceType.INCIDENTS, "57e35aff-e61f-4f3b-b15d-2138743f365e", Optional.of(ResourceType.ALERTS));
        log.info("alerts : " + incident0b);*/

        /*String incident0c = sentinelRestApiCaller.post(ResourceType.INCIDENTS, "57e35aff-e61f-4f3b-b15d-2138743f365e", Optional.of(ResourceType.BOOKMARKS));
        log.info(incident0c);*/

        //Get entities from a incidente !! https://learn.microsoft.com/fr-fr/rest/api/securityinsights/incidents/list-entities?view=rest-securityinsights-2023-11-01&tabs=HTTP#filehashentity
        String incident0d = sentinelRestApiCaller.post(ResourceType.INCIDENTS, "57e35aff-e61f-4f3b-b15d-2138743f365e", Optional.of(ResourceType.ENTITIES));
        log.info("entities : " + incident0d);

        //Get all Entity from a workspace
        /*String incident0a0 = sentinelRestApiCaller.get(ResourceType.ENTITIES, Strings.EMPTY, Optional.empty());
        log.info("all entities : " + incident0a0);*/

    }


}
