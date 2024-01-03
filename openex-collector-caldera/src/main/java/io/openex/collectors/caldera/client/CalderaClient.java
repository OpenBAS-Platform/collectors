package io.openex.collectors.caldera.client;

import io.openex.collectors.caldera.config.CollectorCalderaConfig;
import lombok.RequiredArgsConstructor;
import org.apache.hc.client5.http.ClientProtocolException;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.springframework.stereotype.Service;

import javax.validation.constraints.NotBlank;
import java.io.IOException;

@RequiredArgsConstructor
@Service
public class CalderaClient {

  private static final String KEY_HEADER = "KEY";

  private final CloseableHttpClient httpClient = HttpClientBuilder.create().build();
  private final CollectorCalderaConfig config;

  // -- AGENTS --

  private final static String AGENT_URI = "/agents";

  public String agents() throws ClientProtocolException {
    return this.get(AGENT_URI);
  }

  // -- PRIVATE --

  private String get(@NotBlank final String uri) throws ClientProtocolException {
    try {
      HttpGet httpGet = new HttpGet(this.config.getRestApiV2Url() + uri);
      // Headers
      httpGet.addHeader(KEY_HEADER, this.config.getApiKey());

      return this.httpClient.execute(
          httpGet,
          response -> EntityUtils.toString(response.getEntity())
      );
    } catch (IOException e) {
      throw new ClientProtocolException("Unexpected response for index: " + uri);
    }
  }

}
