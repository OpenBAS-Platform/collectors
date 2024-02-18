package io.openbas.collectors.sentinel.infrastructure;

import io.openbas.collectors.sentinel.infrastructure.config.AuthenticationProperties;
import io.openbas.collectors.sentinel.infrastructure.config.ResourceType;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

@Service
@Slf4j
public class SentinelRestApiCaller {

    public static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSSS'z'", Locale.FRANCE);
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

    private UriComponentsBuilder buildUri(String resourceTypeParam) {
        //String createdTimeParam = LocalDateTime.now(ZoneOffset.UTC).minusMonths(authenticationProperties.getCreatedSince()).format(FORMATTER); FIXME
        String createdTimeParam = LocalDateTime.now(ZoneOffset.UTC).minusMonths(1L).format(FORMATTER);

        return UriComponentsBuilder.fromHttpUrl(authenticationProperties.getEndpoint().getUrl())
                .pathSegment(resourceTypeParam)
                .queryParam(ResourceType.API_VERSION.getParam(), authenticationProperties.getEndpoint().getApiVersion())
                .query(ResourceType.FILTER_CREATED_SINCE_GREATER_THAN.getParam() + createdTimeParam);
    }

    /**
     * @param resourceType principal resource: alertrules, incidents
     * @param resourceId   resource's identifiant
     * @param relationType secondary resource which is in relation with resourceId,  i.e : entities, bookmarks, alerts
     * @param httpMethod
     * @return
     */
    public String executeHttpRequest(ResourceType resourceType, String resourceId, Optional<ResourceType> relationType, HttpMethod httpMethod) {
        URI uri = buildUri(resourceType.getParam())
                .pathSegment(resourceId)
                .pathSegment(relationType.map(ResourceType::getParam).orElse(Strings.EMPTY))
                .build().toUri();

        //log.info("uri : " + uri.getPath());
        return restTemplate.exchange(uri, httpMethod, new HttpEntity<>(headers), String.class).getBody();
    }

    public String get(ResourceType resourceType, String resourceId, Optional<ResourceType> relationType) {
        return executeHttpRequest(resourceType, resourceId, relationType, HttpMethod.GET);
    }

    public String post(ResourceType resourceType, String resourceId, Optional<ResourceType> relationType) {
        return executeHttpRequest(resourceType, resourceId, relationType, HttpMethod.POST);
    }
}
