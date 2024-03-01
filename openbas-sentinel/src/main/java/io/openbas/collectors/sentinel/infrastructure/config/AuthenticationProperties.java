package io.openbas.collectors.sentinel.infrastructure.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties("collector.sentinel")
@Getter
@Setter
public class AuthenticationProperties {

  private boolean enable;
  private String id;
  private int interval = 60;

  private Authority authority;
  private String clientId;
  private String secret;
  private String scope;
  private Endpoint endpoint;
  private Long createdSince;

  @Getter
  @Setter
  public static class Authority {
    private String baseUrl;
    private String tenantId;
    private String url;
  }

  @Getter
  @Setter
  public static class Endpoint {
    private Workspace workspace;
    private String apiVersion;
    private String url;
  }

  @Getter
  @Setter
  public static class Workspace {
    private String subscriptionId;
    private String resourcegroupName;
    private String name;
    private String baseUrl;
  }
}

