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
        System.out.println(alerts);

        //Retrieve actions from alert rules


        //Retrieve incidents
        String incidents = sentinelRestApiCaller.get(HttpMethod.GET, ResourceType.INCIDENTS, Strings.EMPTY, Optional.empty());
        System.out.println(incidents);

        //Retrieve SecurityAlerts from incidents
        String incident0a = sentinelRestApiCaller.get(HttpMethod.GET, ResourceType.INCIDENTS, "6055057e-e14c-4d89-9fce-344dea636534", Optional.of(ResourceType.RELATIONS));
        System.out.println(incident0a);

        String incident0b = sentinelRestApiCaller.get(HttpMethod.POST, ResourceType.INCIDENTS, "6055057e-e14c-4d89-9fce-344dea636534", Optional.of(ResourceType.ALERTS));
        System.out.println(incident0b);

        String incident0c = sentinelRestApiCaller.get(HttpMethod.POST, ResourceType.INCIDENTS, "6055057e-e14c-4d89-9fce-344dea636534", Optional.of(ResourceType.BOOKMARKS));
        System.out.println(incident0c);

        String incident0d = sentinelRestApiCaller.get(HttpMethod.POST, ResourceType.INCIDENTS, "6055057e-e14c-4d89-9fce-344dea636534", Optional.of(ResourceType.ENTITIES));
        System.out.println(incident0d);

        //SecruityAlert from Entity
        String incident0a0 = sentinelRestApiCaller.get(HttpMethod.GET, ResourceType.ENTITIES, "1e203f20-c065-d5d3-65cb-c0d68bfa5001", Optional.empty());
        System.out.println(incident0a0);
    }
}
