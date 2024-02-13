package io.openbas.collectors.sentinel;

import lombok.AllArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;


@AllArgsConstructor
@Service
public class SentinelRestApiCaller {

    private final AuthenticationProperties authenticationProperties;


    public String getAlerts(String accessToken) {
        String endpoint = this.authenticationProperties.getEndpoint().getUrl();
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setBearerAuth(accessToken);

        URI uri = UriComponentsBuilder.fromHttpUrl(endpoint)
                .pathSegment(ResourceType.ALERT_RULES.getParam())
                .queryParam(ResourceType.API_VERSION.getParam(), authenticationProperties.getEndpoint().getApiVersion()).build().toUri();


        return restTemplate.exchange(uri, HttpMethod.GET, new HttpEntity<>(headers), String.class).getBody();
    }

}
