package io.openex.collectors.sentinel.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.Getter;

import java.time.Instant;

import static io.openex.collectors.sentinel.utils.Utils.toInstant;
import static lombok.AccessLevel.NONE;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class IncidentProperties {

  private String title;
  private String providerName;
  private String providerIncidentId;
  private String severity;
  @Getter(NONE)
  private String createdTimeUtc;
  @Getter(NONE)
  private String lastModifiedTimeUtc;

  public Instant getCreatedTimeUtc() {
    return toInstant(this.createdTimeUtc);
  }

  public Instant getLastModifiedTimeUtc() {
    return toInstant(this.lastModifiedTimeUtc);
  }
}
