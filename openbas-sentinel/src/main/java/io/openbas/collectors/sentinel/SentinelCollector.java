package io.openbas.collectors.sentinel;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.openbas.collectors.sentinel.application.SentinelService;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
public class SentinelCollector {
    public static void main(String[] args) throws JsonProcessingException {
        ConfigurableApplicationContext app = SpringApplication.run(SentinelCollector.class, args);
        ((SentinelService) app.getBean("sentinelService")).fetchingDataFromSentinelRestApi();
    }
}
