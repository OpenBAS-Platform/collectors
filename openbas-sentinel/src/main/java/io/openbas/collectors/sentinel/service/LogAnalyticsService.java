package io.openbas.collectors.sentinel.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.shaded.json.JSONObject;
import io.openbas.asset.EndpointService;
import io.openbas.collectors.sentinel.client.LogAnalyticsRestApiCaller;
import io.openbas.collectors.sentinel.config.CollectorSentinelConfig;
import io.openbas.collectors.sentinel.domain.Column;
import io.openbas.collectors.sentinel.domain.QueryResult;
import io.openbas.collectors.sentinel.domain.Table;
import io.openbas.database.model.Asset;
import io.openbas.database.model.Endpoint;
import io.openbas.database.model.InjectExpectation;
import io.openbas.injectExpectation.InjectExpectationService;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.IntStream;

import static io.openbas.collectors.sentinel.config.CollectorSentinelConfig.PRODUCT_NAME;
import static io.openbas.collectors.sentinel.utils.Utils.toInstant;
import static io.openbas.database.model.Endpoint.ENDPOINT_TYPE;
import static io.openbas.injectExpectation.InjectExpectationUtils.getCommandLine;
import static org.springframework.util.StringUtils.hasText;

@RequiredArgsConstructor
@Service
@Log
@ConditionalOnProperty(prefix = "collector.sentinel", name = "enable")
public class LogAnalyticsService {

  private final LogAnalyticsRestApiCaller logAnalyticsRestApiCaller;
  private final InjectExpectationService injectExpectationService;
  private final EndpointService endpointService;
  private final CollectorSentinelConfig config;
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Transactional(rollbackFor = Exception.class)
  public void computePreventionExpectations() {
    QueryResult queryResult = queryResult();
    if (queryResult != null) {

      // Retrieve all expectations from 15 Minutes
      List<InjectExpectation> expectations = this.injectExpectationService
          .preventionExpectationsNotFillFrom(Instant.now().minus(15L, ChronoUnit.MINUTES), this.config.getId());
      log.info("Number of prevention expectations: " + expectations.size());

      if (!expectations.isEmpty()) {
        this.computeExpectationPreventionForAssets(queryResult, expectations);
      }
    }
  }

  // -- PRIVATE --

  private void computeExpectationPreventionForAssets(
      @NotNull final QueryResult queryResult,
      @NotNull final List<InjectExpectation> expectations) {
    List<InjectExpectation> expectationAssets = expectations.stream()
        .filter(e -> e.getAsset() != null)
        .toList();

    expectationAssets.forEach((expectation) -> {
      Asset asset = expectation.getAsset();
      if (ENDPOINT_TYPE.equals(asset.getType())) {
        Endpoint endpoint = this.endpointService.endpoint(asset.getId());
        // Fill expectation detected
        List<String> actions = matchOnAlert(endpoint, queryResult, expectation);
        if (!actions.isEmpty()) {
          this.injectExpectationService.addResultExpectation(
              expectation,
              this.config.getId(),
              PRODUCT_NAME,
              "[".concat(String.join(",", actions)).concat("]")
          );
        }
      }
    });
  }

  private List<String> matchOnAlert(
      @NotNull final Endpoint endpoint,
      @NotNull final QueryResult queryResult,
      @NotNull final InjectExpectation expectation) {
    Optional<Table> tableOpt = extractTable(queryResult);
    if (tableOpt.isPresent()) {
      Table table = tableOpt.get();
      long dateIdx = idx(table, "TimeGenerated");
      long entitiesIdx = idx(table, "entities");
      long descriptionIdx = idx(table, "description");
      long alertSeverityIdx = idx(table, "AlertSeverity");
      long alertLinkIdx = idx(table, "AlertLink");

      if (dateIdx == -1 || entitiesIdx == -1 || descriptionIdx == -1 || alertSeverityIdx == -1 || alertLinkIdx == -1) {
        return List.of();
      }

      // Filter on date
      Predicate<List<String>> dateFilter = row -> {
        String dateString = row.get((int) dateIdx);
        Instant date = toInstant(dateString);
        return date.isAfter(expectation.getCreatedAt());
      };

      // Filter on Host Name
      Predicate<LinkedHashMap<String, Object>> hostNameFilter = e -> endpoint.getHostname()
          .equalsIgnoreCase(Table.getHostName(e));

      // Filter on Command Line
      Predicate<LinkedHashMap<String, Object>> commandLineFilter = e -> getCommandLine(expectation).map(
              commandLine -> hasText(Table.getCommandLine(e)) && Table.getCommandLine(e).replace("\\", "").contains(commandLine))
          .orElse(false);

      return table.getRows()
          .stream()
          // Filter on date
          .filter(dateFilter)
          // Filter on Host Name & Command Line
          .filter(r -> {
            String entitiesString = r.get((int) entitiesIdx);
            try {
              List<LinkedHashMap<String, Object>> entities = this.objectMapper.readValue(entitiesString,
                  new TypeReference<>() {
                  });
              return entities.stream().anyMatch(hostNameFilter) && entities.stream().anyMatch(commandLineFilter);
            } catch (JsonProcessingException e) {
              throw new RuntimeException(e);
            }
          // Return json object
          }).map(r -> {
            try {
              JSONObject json = new JSONObject();
              json.put("description", r.get((int) descriptionIdx));
              json.put("severity", r.get((int) alertSeverityIdx));
              json.put("link", r.get((int) alertLinkIdx));
              return this.objectMapper.writeValueAsString(json);
            } catch (JsonProcessingException e) {
              throw new RuntimeException(e);
            }
          })
          .toList();
    }
    return List.of();
  }

  // -- UTILS --

  private QueryResult queryResult() {
    String jsonResponse = this.logAnalyticsRestApiCaller.retrieveSecurityAlert();
    try {
      return this.objectMapper.readValue(jsonResponse, new TypeReference<>() {
      });
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  private Optional<Table> extractTable(@NotNull final QueryResult queryResult) {
    return queryResult.getTables()
        .stream()
        .filter(t -> "primaryresult".equalsIgnoreCase(t.getName()))
        .findFirst();
  }

  private long idx(@NotNull final Table table, @NotBlank final String property) {
    List<Column> columns = table.getColumns();
    if (columns == null) {
      return -1;
    }
    return IntStream.range(0, columns.size())
        .filter(i -> property.equalsIgnoreCase(columns.get(i).getName()))
        .findFirst()
        .orElse(-1);
  }

}
