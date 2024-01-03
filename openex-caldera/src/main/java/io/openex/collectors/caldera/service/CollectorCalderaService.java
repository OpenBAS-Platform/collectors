package io.openex.collectors.caldera.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.openex.collectors.caldera.client.CalderaClient;
import io.openex.collectors.caldera.model.Agent;
import io.openex.database.model.Endpoint;
import io.openex.service.AssetEndpointService;
import lombok.RequiredArgsConstructor;
import org.apache.hc.client5.http.ClientProtocolException;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static java.time.ZoneOffset.UTC;

@RequiredArgsConstructor
public class CollectorCalderaService implements Runnable {

  private final CalderaClient client;

  private final AssetEndpointService assetEndpointService;

  @Override
  public void run() {
    try {
      List<Agent> agents = this.client.agents();
      List<Endpoint> endpoints = toEndpoint(agents);

      List<Endpoint> toCreate = new ArrayList<>();
      List<Endpoint> toUpdate = new ArrayList<>();
      endpoints.forEach((endpoint -> {
        Optional<Endpoint> existing = this.assetEndpointService.endpointFromExternalId(endpoint.getExternalId());
        existing.ifPresentOrElse((e) -> {
              // Update
              mergeEndpoint(e, endpoint);
              toUpdate.add(e);
            },
            // Create
            () -> toCreate.add(endpoint)
        );
      }));
      this.assetEndpointService.createEndpoints(toCreate);
      this.assetEndpointService.updateEndpoints(toUpdate);
    } catch (ClientProtocolException | JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  // -- PRIVATE --

  private List<Endpoint> toEndpoint(@NotNull final List<Agent> agents) {
    return agents.stream()
        .map((agent) -> {
          Endpoint endpoint = new Endpoint();
          endpoint.setExternalId(agent.getPaw());
          endpoint.setName(agent.getPaw());
          endpoint.setDescription("Connected with " + agent.getUsername() + " on privilege " + agent.getPrivilege());
          endpoint.setIps(agent.getHost_ip_addrs());
          endpoint.setHostname(agent.getHost());
          endpoint.setPlatform(toPlatform(agent.getPlatform()));
          endpoint.setLastSeen(toInstant(agent.getLast_seen()));
          return endpoint;
        })
        .toList();
  }

  private Endpoint.PLATFORM_TYPE toPlatform(@NotBlank final String platform) {
    return switch (platform) {
      case "linux" -> Endpoint.PLATFORM_TYPE.LINUX;
      case "windows" -> Endpoint.PLATFORM_TYPE.WINDOWS;
      default -> throw new IllegalArgumentException("This platform is not supported : " + platform);
    };
  }

  private Instant toInstant(@NotNull final String lastSeen) {
    String pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(pattern, Locale.getDefault());
    LocalDateTime localDateTime = LocalDateTime.parse(lastSeen, dateTimeFormatter);
    ZonedDateTime zonedDateTime = localDateTime.atZone(UTC);
    return zonedDateTime.toInstant();
  }

  private void mergeEndpoint(@NotNull final Endpoint source, @NotNull final Endpoint external) {
    source.setExternalId(external.getExternalId());
    source.setName(external.getName());
    source.setDescription(external.getDescription());
    source.setIps(external.getIps());
    source.setHostname(external.getHostname());
    source.setPlatform(external.getPlatform());
  }

}
