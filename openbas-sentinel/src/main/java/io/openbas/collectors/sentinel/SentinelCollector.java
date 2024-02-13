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

        Client client = (Client) app.getBean("client");
        String accessToken = client.fetchToken().accessToken();

        SentinelRestApiCaller sentinelRestApiCaller = (SentinelRestApiCaller) app.getBean("sentinelRestApiCaller");
        String alerts = sentinelRestApiCaller.getAlerts(accessToken);
        System.out.println(alerts);

    }

}
