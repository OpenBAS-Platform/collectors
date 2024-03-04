package io.openbas.collectors.sentinel.application;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.openbas.asset.EndpointService;
import io.openbas.collectors.sentinel.domain.*;
import io.openbas.collectors.sentinel.infrastructure.SentinelRestApiCaller;
import io.openbas.collectors.sentinel.infrastructure.config.ResourceType;
import io.openbas.database.model.Asset;
import io.openbas.database.model.Endpoint;
import io.openbas.database.model.InjectExpectation;
import io.openbas.injectExpectation.InjectExpectationService;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;

import static io.openbas.database.model.Endpoint.ENDPOINT_TYPE;
import static io.openbas.injectExpectation.InjectExpectationUtils.computeExpectationGroup;
import static org.springframework.util.StringUtils.hasText;

@RequiredArgsConstructor
@Service
@Log
public class SentinelService {
  private final SentinelRestApiCaller sentinelRestApiCaller;
  private final InjectExpectationService injectExpectationService;
  private final EndpointService endpointService;
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Transactional(rollbackFor = Exception.class)
  public void computeDetectionExpectations() {
    List<Incident> incidents = incidents();
    incidents.forEach(this::processIncident);
    log.info("Number of incidents: " + incidents.size());

    if (!incidents.isEmpty()) {
      List<InjectExpectation> expectations = this.injectExpectationService
          .detectionExpectationsNotFill();
      log.info("Number of expectations: " + expectations.size());

      if (!expectations.isEmpty()) {
        this.computeExpectationForAssets(incidents, expectations);
        this.computeExpectationForAssetGroups(expectations);
      }
    }
  }

  // -- PRIVATE -

  private void computeExpectationForAssets(
      @NotNull final List<Incident> incidents,
      @NotNull final List<InjectExpectation> expectations) {
    List<InjectExpectation> expectationAssets = expectations.stream()
        .filter(e -> e.getAsset() != null)
        .toList();

    expectationAssets.forEach((expectation) -> {
      Asset asset = expectation.getAsset();
      // Maximum time for detection
      if (isExpired(expectation)) {
        expectation.setResult("Not detected");
        expectation.setScore(0);
        this.injectExpectationService.update(expectation);
      } else if (ENDPOINT_TYPE.equals(asset.getType())) {
        Endpoint endpoint = this.endpointService.endpoint(asset.getId());
        // Fill expectation detected
        if (match(endpoint, incidents, expectation.getCreatedAt())) {
          expectation.setResult("Detected by Microsoft Sentinel");
          expectation.setScore(expectation.getExpectedScore());
          this.injectExpectationService.update(expectation);
        }
      }
    });
  }

  private void computeExpectationForAssetGroups(@NotNull final List<InjectExpectation> expectations) {
    List<InjectExpectation> expectationAssetGroups = expectations.stream()
        .filter(e -> e.getAssetGroup() != null)
        .toList();

    expectationAssetGroups.forEach((expectationAssetGroup -> {
      List<InjectExpectation> expectationAssets = this.injectExpectationService.detectionExpectationsForAssets(
          expectationAssetGroup.getInject(), expectationAssetGroup.getAssetGroup()
      );
      // Every expectation assets are filled
      if (expectationAssets.stream().noneMatch(e -> e.getResult() == null)) {
        computeExpectationGroup(expectationAssetGroup, expectationAssets);
        this.injectExpectationService.update(expectationAssetGroup);
      }
    }));
  }

  private boolean match(
      @NotNull final Endpoint endpoint,
      @NotNull final List<Incident> incidents,
      @NotNull final Instant after) {

    // FIXME: Extract command line from Caldera to InjectStatus.Execution reporting
    // FIXME: Match with alert command line

    return incidents.stream()
        .filter(i -> i.getProperties().getLastModifiedTimeUtc().isAfter(after))
        .anyMatch(incident -> {
          List<Entity> entities = incident.getEntities()
              .stream()
              .filter(entity -> endpoint.getHostname().equalsIgnoreCase(entity.getProperties().getHostName()))
              .toList();
          return !entities.isEmpty();
        });
  }

  private boolean isExpired(@NotNull final InjectExpectation expectation) {
    return expectation.getCreatedAt().isBefore(Instant.now().minus(15L, ChronoUnit.MINUTES));
  }

  private List<Incident> incidents() {
    String jsonResponse = this.sentinelRestApiCaller.get(
        ResourceType.INCIDENTS,
        "",
        Optional.empty()
    );

    try {
      ListOfIncidents listOfIncidents = this.objectMapper.readValue(jsonResponse, new TypeReference<>() {
      });
      return listOfIncidents.getValue();
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  private void processIncident(Incident incident) {
    try {
      List<Entity> entities = entities(incident);
      incident.setEntities(entities);
      List<Alert> alerts = alerts(incident);
      incident.setAlerts(alerts);
    } catch (Exception e) {
      log.log(Level.SEVERE, "Error processing incident: " + incident.getName(), e);
    }
  }

  private List<Entity> entities(final Incident incident) {
    String jsonResponse = this.sentinelRestApiCaller.post(
        ResourceType.INCIDENTS,
        incident.getName(),
        Optional.of(ResourceType.ENTITIES)
    );

    if (!hasText(jsonResponse)) {
      return List.of();
    }

    try {
      ListOfEntities listOfEntities = this.objectMapper.readValue(jsonResponse, new TypeReference<>() {
      });
      return listOfEntities.getEntities();
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  private List<Alert> alerts(final Incident incident) {
    String jsonResponse = this.sentinelRestApiCaller.post(
        ResourceType.INCIDENTS,
        incident.getName(),
        Optional.of(ResourceType.ALERTS)
    );

    if (!hasText(jsonResponse)) {
      return List.of();
    }

    try {
      ListOfAlerts listOfAlerts = this.objectMapper.readValue(jsonResponse, new TypeReference<>() {
      });
      return listOfAlerts.getValue();
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

}
