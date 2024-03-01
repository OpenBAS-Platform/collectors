package io.openbas.collectors.users.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import jakarta.validation.constraints.NotBlank;

@Component
@ConfigurationProperties(prefix = "collector.users")
@Getter
@Setter
public class UsersCollectorConfig {

  @NotBlank
  private Boolean enable;
}
