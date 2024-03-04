package io.openbas.collectors.sentinel.client;

import io.openbas.collectors.sentinel.config.CollectorSentinelConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

import static org.apache.hc.core5.http.HttpHeaders.ACCEPT;
import static org.apache.hc.core5.http.HttpHeaders.AUTHORIZATION;

public abstract class RestApiCaller<T extends AuthenticationClient> {

  protected final T authenticationClient;
  protected final CloseableHttpClient httpClient = HttpClientBuilder.create().build();
  protected final CollectorSentinelConfig collectorSentinelConfig;
  protected final List<Header> headers;

  public RestApiCaller(
      T authenticationClient,
      CollectorSentinelConfig collectorSentinelConfig
  ) throws IOException, ExecutionException, InterruptedException {
    this.authenticationClient = authenticationClient;
    this.collectorSentinelConfig = collectorSentinelConfig;
    this.headers = this.createHeaders();
  }

  private List<Header> createHeaders() throws IOException, ExecutionException, InterruptedException {
    List<Header> headers = new ArrayList<>();
    headers.add(new BasicHeader(AUTHORIZATION, "Bearer " + fetchAccessTokenLog()));
    headers.add(new BasicHeader(ACCEPT, MediaType.APPLICATION_JSON));
    return headers;
  }

  private String fetchAccessTokenLog() throws IOException, ExecutionException, InterruptedException {
    return this.authenticationClient.fetchToken().accessToken();
  }

}
