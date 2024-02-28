package io.openex.collectors.sentinel.application;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.openex.InjectExpectation.InjectExpectationService;
import io.openex.asset.EndpointService;
import io.openex.collectors.sentinel.domain.*;
import io.openex.collectors.sentinel.infrastructure.SentinelRestApiCaller;
import io.openex.collectors.sentinel.infrastructure.config.ResourceType;
import io.openex.database.model.Asset;
import io.openex.database.model.Endpoint;
import io.openex.database.model.InjectExpectation;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;

import static io.openex.database.model.Endpoint.ENDPOINT_TYPE;
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
  public void computeDetectionExpectations() { // TODO: Validation by group or individual ?
    List<Incident> incidents = incidents();
    incidents.forEach(this::processIncident);
    log.info("Number of incidents: " + incidents.size());

    if (!incidents.isEmpty()) {
      List<InjectExpectation> expectations = this.injectExpectationService
          .detectionExpectationsNotFill();
      log.info("Number of expectations: " + expectations.size());
      expectations.forEach((expectation) -> {
        Asset asset = expectation.getAsset();
        // Maximum time for detection
        if (expectation.getCreatedAt().isBefore(Instant.now().minus(15L, ChronoUnit.MINUTES))) {
          expectation.setResult("Not detected");
          expectation.setScore(0);
          this.injectExpectationService.updateInjectExpectation(expectation);
        } else if (ENDPOINT_TYPE.equals(asset.getType())) {
          Endpoint endpoint = this.endpointService.endpoint(asset.getId());
          // Fill expectation detected
          if (match(endpoint, incidents)) {
            expectation.setResult("Something relative to the alert");
            expectation.setScore(expectation.getExpectedScore());
            this.injectExpectationService.updateInjectExpectation(expectation);
          }
        }
      });
    }
  }

  // -- PRIVATE -

  private boolean match(Endpoint endpoint, List<Incident> incidents) {
    return incidents.stream()
        .anyMatch(incident -> {
          List<Entity> entities = incident.getEntities()
              .stream()
              .filter(entity -> endpoint.getHostname().equals(entity.getProperties().getHostName()))
              .toList();
          return !entities.isEmpty();
        });
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
