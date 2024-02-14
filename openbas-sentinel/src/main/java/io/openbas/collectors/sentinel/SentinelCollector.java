package io.openbas.collectors.sentinel;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

@SpringBootApplication
public class SentinelCollector {
    public static void main(String[] args) throws IOException, ExecutionException, InterruptedException {
        ConfigurableApplicationContext app = SpringApplication.run(SentinelCollector.class, args);

        SentinelRestApiCaller sentinelRestApiCaller = (SentinelRestApiCaller) app.getBean("sentinelRestApiCaller");
        String alerts = sentinelRestApiCaller.getListOfResources(ResourceType.ALERT_RULES);
        System.out.println(alerts);

        String incidents = sentinelRestApiCaller.getListOfResources(ResourceType.INCIDENTS);
        System.out.println(incidents);

        String incident0 = sentinelRestApiCaller.getOneResource(ResourceType.INCIDENTS, "81e0a2fc-fc12-4665-8a63-f7f9ee1326be");
        System.out.println(incidents);
    }
}
