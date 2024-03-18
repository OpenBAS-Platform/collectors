package io.openbas.collectors.sentinel.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.shaded.json.JSONObject;
import io.openbas.asset.EndpointService;
import io.openbas.collectors.sentinel.client.AzureRestApiCaller;
import io.openbas.collectors.sentinel.client.resourcetype.AzureResourceType;
import io.openbas.collectors.sentinel.config.CollectorSentinelConfig;
import io.openbas.collectors.sentinel.domain.*;
import io.openbas.database.model.Asset;
import io.openbas.database.model.Endpoint;
import io.openbas.database.model.InjectExpectation;
import io.openbas.injectExpectation.InjectExpectationService;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.logging.Level;

import static io.openbas.collectors.sentinel.config.CollectorSentinelConfig.PRODUCT_NAME;
import static io.openbas.collectors.sentinel.utils.Utils.isExpired;
import static io.openbas.database.model.Endpoint.ENDPOINT_TYPE;
import static io.openbas.injectExpectation.InjectExpectationUtils.getCommandLine;
import static org.springframework.util.StringUtils.hasText;

@RequiredArgsConstructor
@Service
@Log
@ConditionalOnProperty(prefix = "collector.sentinel", name = "enable")
public class SentinelService {

  private final AzureRestApiCaller azureRestApiCaller;
  private final InjectExpectationService injectExpectationService;
  private final EndpointService endpointService;
  private final CollectorSentinelConfig config;
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Transactional(rollbackFor = Exception.class)
  public void computeDetectionExpectations() {
    List<Incident> incidents = incidents();
    if (incidents != null) {
      if (!incidents.isEmpty()) {
        incidents.forEach(this::processIncident);
        log.info("Number of incidents: " + incidents.size());

        List<InjectExpectation> expectations = this.injectExpectationService
            .detectionExpectationsNotFill(this.config.getId());
        log.info("Number of detection expectations: " + expectations.size());

        if (!expectations.isEmpty()) {
          this.computeExpectationDetectionForAssets(incidents, expectations);
          this.computeExpectationDetectionForAssetGroups(expectations);
        }
      }
    }
  }

  // -- PRIVATE -

  private void computeExpectationDetectionForAssets(
      @NotNull final List<Incident> incidents,
      @NotNull final List<InjectExpectation> expectations) {
    List<InjectExpectation> expectationAssets = expectations.stream()
        .filter(e -> e.getAsset() != null)
        .toList();

    expectationAssets.forEach((expectation) -> {
      Asset asset = expectation.getAsset();
      // Maximum time for detection
      if (isExpired(expectation)) {
        this.injectExpectationService.computeExpectation(
            expectation,
            this.config.getId(),
            PRODUCT_NAME,
            "Not detected",
            false
        );
      } else if (ENDPOINT_TYPE.equals(asset.getType())) {
        Endpoint endpoint = this.endpointService.endpoint(asset.getId());
        // Fill expectation detected
        List<String> actions = matchOnIncident(endpoint, incidents, expectation);
        if (!actions.isEmpty()) {
          this.injectExpectationService.computeExpectation(
              expectation,
              this.config.getId(),
              PRODUCT_NAME,
              "[".concat(String.join(",", actions)).concat("]"),
              true
          );
        }
      }
    });
  }

  private void computeExpectationDetectionForAssetGroups(@NotNull final List<InjectExpectation> expectations) {
    List<InjectExpectation> expectationAssetGroups = expectations.stream()
        .filter(e -> e.getAssetGroup() != null)
        .toList();

    expectationAssetGroups.forEach((expectationAssetGroup -> {
      List<InjectExpectation> expectationAssets = this.injectExpectationService.detectionExpectationsForAssets(
          expectationAssetGroup.getInject(), expectationAssetGroup.getAssetGroup()
      );
      // Every expectation assets are filled
      if (expectationAssets.stream().noneMatch(e -> e.getResults().isEmpty())) {
        this.injectExpectationService.computeExpectationGroup(
            expectationAssetGroup,
            expectationAssets,
            this.config.getId(),
            PRODUCT_NAME
        );
      }
    }));
  }

  private List<String> matchOnIncident(
      @NotNull final Endpoint endpoint,
      @NotNull final List<Incident> incidents,
      @NotNull final InjectExpectation expectation) {

    // Filter on date
    Predicate<Incident> dateFilter = incident -> incident.getProperties()
        .getLastModifiedTimeUtc()
        .isAfter(expectation.getCreatedAt().minus(30, ChronoUnit.MINUTES));

    // Filter on Host Name
    Predicate<Entity> hostNameFilter = entity -> endpoint.getHostname().equalsIgnoreCase(entity.getHostName());

    // Filter on Command Line
    Predicate<Entity> commandLineFilter = entity -> getCommandLine(expectation)
        .map(cl -> hasText(entity.getCommandLine()) && entity.getCommandLine().replace("\\", "").contains(cl))
        .orElse(false);

    return incidents.stream()
        // Filter on date
        .filter(dateFilter)
        // Filter on Host Name & Command Line
        .filter(incident -> incident.getEntities().stream().anyMatch(hostNameFilter)
            && incident.getEntities().stream().anyMatch(commandLineFilter))
        // Return json object
        .map(i -> {
          try {
            JSONObject json = new JSONObject();
            json.put("title", i.getProperties().getTitle());
            json.put("severity", i.getProperties().getSeverity());
            json.put("link", i.getProperties().getIncidentUrl());
            return this.objectMapper.writeValueAsString(json);
          } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
          }
        })
        .toList();
  }

  // -- UTILS --

  private List<Incident> incidents() {
    String jsonResponse = this.azureRestApiCaller.get(
        AzureResourceType.INCIDENTS,
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
    String jsonResponse = this.azureRestApiCaller.post(
        AzureResourceType.INCIDENTS,
        incident.getName(),
        Optional.of(AzureResourceType.ENTITIES)
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
    String jsonResponse = this.azureRestApiCaller.post(
        AzureResourceType.INCIDENTS,
        incident.getName(),
        Optional.of(AzureResourceType.ALERTS)
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
