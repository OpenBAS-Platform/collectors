package io.openbas.collectors.sentinel.infrastructure;

import io.openbas.collectors.sentinel.infrastructure.config.AuthenticationProperties;
import io.openbas.collectors.sentinel.infrastructure.config.ResourceType;
import io.openbas.collectors.sentinel.utils.Utils;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

import static org.apache.hc.core5.http.HttpHeaders.ACCEPT;
import static org.apache.hc.core5.http.HttpHeaders.AUTHORIZATION;

@Service
@Slf4j
public class SentinelRestApiCaller {

  private final Client client;
  private final CloseableHttpClient httpClient = HttpClientBuilder.create().build();
  private final AuthenticationProperties authenticationProperties;
  private final List<Header> headers;

  public SentinelRestApiCaller(
      Client client,
      AuthenticationProperties authenticationProperties
  ) throws IOException, ExecutionException, InterruptedException {
    this.client = client;
    this.authenticationProperties = authenticationProperties;
    this.headers = createHeaders();
  }

  private List<Header> createHeaders() throws IOException, ExecutionException, InterruptedException {
    List<Header> headers = new ArrayList<>();
    headers.add(new BasicHeader(AUTHORIZATION, "Bearer " + fetchAccessToken()));
    headers.add(new BasicHeader(ACCEPT, MediaType.APPLICATION_JSON));
    return headers;
  }

  private String fetchAccessToken() throws IOException, ExecutionException, InterruptedException {
    return client.fetchToken().accessToken();
  }

  private UriComponentsBuilder buildUri(String resourceTypeParam) {
    String createdTimeParam = LocalDateTime.now(ZoneOffset.UTC)
        .minusMinutes(15L)
        .format(Utils.FORMATTER);

    return UriComponentsBuilder.fromHttpUrl(authenticationProperties.getEndpoint().getUrl())
        .pathSegment(resourceTypeParam)
        .queryParam(ResourceType.API_VERSION.getParam(), authenticationProperties.getEndpoint().getApiVersion())
        .query(ResourceType.FILTER_UPDATED_SINCE_GREATER_THAN.getParam() + createdTimeParam);
  }

  public String get(ResourceType resourceType, String resourceId, Optional<ResourceType> relationType) {
    URI uri = buildUri(resourceType.getParam())
        .pathSegment(resourceId)
        .pathSegment(relationType.map(ResourceType::getParam).orElse(""))
        .build()
        .toUri();
    try {
      HttpGet httpGet = new HttpGet(uri);
      // Headers
      for (Header header : this.headers) {
        httpGet.setHeader(header);
      }

      return this.httpClient.execute(
          httpGet,
          response -> EntityUtils.toString(response.getEntity())
      );
    } catch (IOException e) {
      throw new RuntimeException("Unexpected response for request on: " + uri);
    }
  }

  public String post(ResourceType resourceType, String resourceId, Optional<ResourceType> relationType) {
    URI uri = buildUri(resourceType.getParam())
        .pathSegment(resourceId)
        .pathSegment(relationType.map(ResourceType::getParam).orElse(""))
        .build()
        .toUri();
    try {
      HttpPost httpPost = new HttpPost(uri);
      // Headers
      for (Header header : this.headers) {
        httpPost.setHeader(header);
      }
      StringEntity httpBody = new StringEntity("");
      httpPost.setEntity(httpBody);

      return this.httpClient.execute(
          httpPost,
          response -> EntityUtils.toString(response.getEntity())
      );
    } catch (IOException e) {
      throw new RuntimeException("Unexpected response for request on: " + uri);
    }
  }
}
