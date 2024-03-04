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

  private static final String BASE_URL = "https://management.azure.com/";
  private static final String API_VERSION = "2023-12-01-preview";

  private boolean enable;
  private String id;
  private int interval = 60;

  private Authority authority;
  private String clientId;
  private String clientSecret;
  private final String scope = "https://management.azure.com/.default";

  private Subscription subscription;

  public String getApiVersion() {
    return API_VERSION;
  }

  @Getter
  @Setter
  public static class Authority {
    private String baseUrl;
    private String tenantId;
    public String getUrl() {
      return this.baseUrl + "/" + this.tenantId;
    }
  }

  @Getter
  @Setter
  public static class Subscription {
    private String id;
    private ResourceGroups resourceGroups;
    private Workspace workspace;

    private String getUrl() {
      return BASE_URL + "subscriptions/" + this.id;
    }

    public String getSecurityInsightsUrl() {
      return this.getUrl() + this.resourceGroups.getUrl() + this.workspace.getUrl() + "/providers/Microsoft.SecurityInsights/";
    }
  }

  @Getter
  @Setter
  public static class ResourceGroups {
    private String name;

    private String getUrl() {
      return "/resourcegroups/" + this.name;
    }
  }

  @Getter
  @Setter
  public static class Workspace {
    private String name;

    private String getUrl() {
      return "/providers/microsoft.operationalinsights/workspaces/" + this.name;
    }
  }
}

