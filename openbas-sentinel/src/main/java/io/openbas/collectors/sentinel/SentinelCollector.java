package io.openbas.collectors.sentinel;

import org.apache.logging.log4j.util.Strings;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpMethod;

import java.util.Optional;

@SpringBootApplication
public class SentinelCollector {
    public static void main(String[] args) {
        ConfigurableApplicationContext app = SpringApplication.run(SentinelCollector.class, args);

        SentinelRestApiCaller sentinelRestApiCaller = (SentinelRestApiCaller) app.getBean("sentinelRestApiCaller");

        //Retrieve alerts
        String alerts = sentinelRestApiCaller.get(HttpMethod.GET, ResourceType.ALERT_RULES, Strings.EMPTY, Optional.empty());
        //System.out.println(alerts);

        //Retrieve actions from alert rules


        //Retrieve incidents
        String incidents = sentinelRestApiCaller.get(HttpMethod.GET, ResourceType.INCIDENTS, Strings.EMPTY, Optional.empty());
        //System.out.println(incidents);

        //Retrieve SecurityAlerts from incidents
        String incident0a = sentinelRestApiCaller.get(HttpMethod.GET, ResourceType.INCIDENTS, "57e35aff-e61f-4f3b-b15d-2138743f365e", Optional.of(ResourceType.RELATIONS));
        System.out.println("relations : "+ incident0a);

        String incident0b = sentinelRestApiCaller.get(HttpMethod.POST, ResourceType.INCIDENTS, "57e35aff-e61f-4f3b-b15d-2138743f365e", Optional.of(ResourceType.ALERTS));
        System.out.println("alerts : "+ incident0b);

        String incident0c = sentinelRestApiCaller.get(HttpMethod.POST, ResourceType.INCIDENTS, "57e35aff-e61f-4f3b-b15d-2138743f365e", Optional.of(ResourceType.BOOKMARKS));
        //System.out.println(incident0c);

        //Get entities from a incidente !! https://learn.microsoft.com/fr-fr/rest/api/securityinsights/incidents/list-entities?view=rest-securityinsights-2023-11-01&tabs=HTTP#filehashentity
        String incident0d = sentinelRestApiCaller.get(HttpMethod.POST, ResourceType.INCIDENTS, "57e35aff-e61f-4f3b-b15d-2138743f365e", Optional.of(ResourceType.ENTITIES));
        System.out.println("entities : "+ incident0d);

        //Get all Entity from a workspace
        String incident0a0 = sentinelRestApiCaller.get(HttpMethod.GET, ResourceType.ENTITIES, Strings.EMPTY, Optional.empty());
        System.out.println(incident0a0);
    }
}
