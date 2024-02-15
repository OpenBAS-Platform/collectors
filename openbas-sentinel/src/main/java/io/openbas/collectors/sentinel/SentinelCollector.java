package io.openbas.collectors.sentinel;

import org.apache.logging.log4j.util.Strings;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

@SpringBootApplication
@Slf4j
public class SentinelCollector {
    public static void main(String[] args) {
        ConfigurableApplicationContext app = SpringApplication.run(SentinelCollector.class, args);

        SentinelRestApiCaller sentinelRestApiCaller = (SentinelRestApiCaller) app.getBean("sentinelRestApiCaller");

        //Retrieve alerts
        String alerts = sentinelRestApiCaller.get(ResourceType.ALERT_RULES, Strings.EMPTY, Optional.empty());
        //log.info(alerts);

        //Retrieve actions from alert rules
        String actionsAlerts = sentinelRestApiCaller.get(ResourceType.ALERT_RULES, "BuiltInFusion", Optional.of(ResourceType.ACTIONS));
        log.info("actions : " + actionsAlerts);

        //Retrieve incidents
        String incidents = sentinelRestApiCaller.get(ResourceType.INCIDENTS, Strings.EMPTY, Optional.empty());
        //log.info(incidents);

        //Retrieve SecurityAlerts from incidents
        String incident0a = sentinelRestApiCaller.get(ResourceType.INCIDENTS, "57e35aff-e61f-4f3b-b15d-2138743f365e", Optional.of(ResourceType.RELATIONS));
        log.info("relations : " + incident0a);

        String incident0b = sentinelRestApiCaller.post(ResourceType.INCIDENTS, "57e35aff-e61f-4f3b-b15d-2138743f365e", Optional.of(ResourceType.ALERTS));
        log.info("alerts : " + incident0b);

        String incident0c = sentinelRestApiCaller.post(ResourceType.INCIDENTS, "57e35aff-e61f-4f3b-b15d-2138743f365e", Optional.of(ResourceType.BOOKMARKS));
        //log.info(incident0c);

        //Get entities from a incidente !! https://learn.microsoft.com/fr-fr/rest/api/securityinsights/incidents/list-entities?view=rest-securityinsights-2023-11-01&tabs=HTTP#filehashentity
        String incident0d = sentinelRestApiCaller.post(ResourceType.INCIDENTS, "57e35aff-e61f-4f3b-b15d-2138743f365e", Optional.of(ResourceType.ENTITIES));
        log.info("entities : " + incident0d);

        //Get all Entity from a workspace
        String incident0a0 = sentinelRestApiCaller.get(ResourceType.ENTITIES, Strings.EMPTY, Optional.empty());
        log.info("all entities : " + incident0a0);
    }
}
