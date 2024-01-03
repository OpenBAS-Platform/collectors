package io.openex.collectors.caldera.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.openex.collectors.caldera.config.CollectorCalderaConfig;
import io.openex.collectors.caldera.model.Agent;
import lombok.RequiredArgsConstructor;
import org.apache.hc.client5.http.ClientProtocolException;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.springframework.stereotype.Service;

import javax.validation.constraints.NotBlank;
import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
@Service
public class CalderaClient {

  private static final String KEY_HEADER = "KEY";

  private final CollectorCalderaConfig config;
  private final CloseableHttpClient httpClient = HttpClientBuilder.create().build();
  private final ObjectMapper objectMapper = new ObjectMapper();

  // -- AGENTS --

  private final static String AGENT_URI = "/agents";

  public List<Agent> agents() throws ClientProtocolException, JsonProcessingException {
    String jsonResponse = this.get(AGENT_URI);
    return this.objectMapper.readValue(jsonResponse, new TypeReference<>() {
    });
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
      throw new ClientProtocolException("Unexpected response for request on: " + uri);
    }
  }

}
