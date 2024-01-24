package io.openex.collectors.caldera.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.openex.collectors.caldera.client.CollectorCalderaClient;
import io.openex.collectors.caldera.config.CollectorCalderaConfig;
import io.openex.collectors.caldera.model.Agent;
import io.openex.database.model.Endpoint;
import io.openex.service.AssetEndpointService;
import io.openex.service.AssetEndpointService.EndpointDBUpdate;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.apache.hc.client5.http.ClientProtocolException;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static java.time.ZoneOffset.UTC;

@RequiredArgsConstructor
public class CollectorCalderaService implements Runnable {

  private final CollectorCalderaClient client;
  private final CollectorCalderaConfig config;

  private final AssetEndpointService assetEndpointService;

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public void run() {
    try {
      List<Agent> agents = this.client.agents();
      List<Endpoint> endpoints = toEndpoint(agents);

      List<Endpoint> toCreate = new ArrayList<>();
      List<EndpointDBUpdate> toUpdate = new ArrayList<>();
      endpoints.forEach((endpoint -> {
        Optional<String> existingOptional = this.assetEndpointService
            .findIdBySource(this.config.getId(), endpoint.getSources().get(this.config.getId()));
        existingOptional.ifPresentOrElse((existing) -> {
              // Update
              String blob = endpoint.getBlobs().get(this.config.getId());
              EndpointDBUpdate update = new EndpointDBUpdate(existing, this.config.getId(), blob, endpoint.getLastSeen(), Instant.now());
              toUpdate.add(update);
            },
            // Create
            () -> toCreate.add(endpoint)
        );
      }));

      this.assetEndpointService.createEndpoints(toCreate);
      this.assetEndpointService.updateEndpoints(toUpdate);
      System.out.println("Caldera collector provisioning based on " + (toCreate.size() + toUpdate.size()) + " assets");
    } catch (ClientProtocolException | JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  // -- PRIVATE --

  private List<Endpoint> toEndpoint(@NotNull final List<Agent> agents) {
    final String collectorId = this.config.getId();
    return agents.stream()
        .map((agent) -> {
          Endpoint endpoint = new Endpoint();
          endpoint.setSources(new HashMap<>() {{
            put(collectorId, agent.getPaw());
          }});
          endpoint.setBlobs(new HashMap<>() {{
            try {
              put(collectorId, objectMapper.writeValueAsString(agent)); // agent blob
            } catch (JsonProcessingException e) {
              throw new RuntimeException(e);
            }
          }});
          endpoint.setName(agent.getHost() + " - " + agent.getPaw());
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
      case "linux" -> Endpoint.PLATFORM_TYPE.Linux;
      case "windows" -> Endpoint.PLATFORM_TYPE.Windows;
      case "darwin" -> Endpoint.PLATFORM_TYPE.Darwin;
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

}
