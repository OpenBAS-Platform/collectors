package io.openex.collectors.caldera.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import javax.validation.constraints.NotBlank;

@Setter
@Component
@ConfigurationProperties(prefix = "collector.caldera")
public class CollectorCalderaConfig {

  private final static String REST_URI = "/api/v2";

  @Getter
  private boolean enable;

  @NotBlank
  private String url;

  @Getter
  @NotBlank
  private String apiKey;

  public String getRestApiV2Url() {
    return url + REST_URI;
  }
}
