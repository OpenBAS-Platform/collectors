package io.openex.collectors.mitre_attack.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import jakarta.validation.constraints.NotBlank;

@Component
@ConfigurationProperties(prefix = "collector.mitre-attack")
@Getter
@Setter
public class MitreAttackCollectorConfig {

  @NotBlank
  private Boolean enable = true;
}
