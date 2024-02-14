package io.openbas.collectors.sentinel;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.concurrent.ExecutionException;

@Service

public class SentinelRestApiCaller {

    private final Client client;
    private final RestTemplate restTemplate;
    private final AuthenticationProperties authenticationProperties;
    private final HttpHeaders headers;

    public SentinelRestApiCaller(Client client, RestTemplate restTemplate, AuthenticationProperties authenticationProperties) throws IOException, ExecutionException, InterruptedException {
        this.client = client;
        this.restTemplate = restTemplate;
        this.authenticationProperties = authenticationProperties;
        this.headers = createHeaders();
    }

    private HttpHeaders createHeaders() throws IOException, ExecutionException, InterruptedException {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(fetchAccessToken());
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        return headers;
    }

    private String fetchAccessToken() throws IOException, ExecutionException, InterruptedException {
        return client.fetchToken().accessToken();
    }

    private URI buildUri(String resourceTypeParam) {
        return UriComponentsBuilder.fromHttpUrl(authenticationProperties.getEndpoint().getUrl())
                .pathSegment(resourceTypeParam)
                .queryParam(ResourceType.API_VERSION.getParam(), authenticationProperties.getEndpoint().getApiVersion())
                .build().toUri();
    }

    public String getAlerts() {
        URI uri = buildUri(ResourceType.ALERT_RULES.getParam());
        return restTemplate.exchange(uri, HttpMethod.GET, new HttpEntity<>(headers), String.class).getBody();
    }

    public String getIncidents() {
        URI uri = buildUri(ResourceType.INCIDENTS.getParam());
        return restTemplate.exchange(uri, HttpMethod.GET, new HttpEntity<>(headers), String.class).getBody();
    }
}
