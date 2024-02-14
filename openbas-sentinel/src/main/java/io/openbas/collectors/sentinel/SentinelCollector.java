package io.openbas.collectors.sentinel;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.JSONPObject;
import com.fasterxml.jackson.databind.util.JSONWrappedObject;
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
        String alerts = sentinelRestApiCaller.getAlerts();
        System.out.println(alerts);

        String incidents = sentinelRestApiCaller.getIncidents();
        System.out.println(incidents);
    }

}
