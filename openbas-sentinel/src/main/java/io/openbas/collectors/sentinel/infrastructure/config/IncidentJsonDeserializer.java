package io.openbas.collectors.sentinel.infrastructure.config;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import io.openbas.collectors.sentinel.domain.Incident;
import io.openbas.collectors.sentinel.domain.ListOfIncidents;
import io.openbas.collectors.sentinel.domain.Provider;

import java.io.IOException;
import java.util.List;
import java.util.stream.StreamSupport;

public class IncidentJsonDeserializer extends JsonDeserializer<ListOfIncidents> {

    @Override
    public ListOfIncidents deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        JsonNode node = jp.getCodec().readTree(jp);
        List<Incident> incidents = StreamSupport.stream(node.get("value").spliterator(), false)
                .map(this::createIncidentFromJsonNode)
                .toList();

        ListOfIncidents listOfIncidents = ListOfIncidents.builder().incidents(incidents).build();

        return listOfIncidents;
    }

    // Method to create an Incident from a JsonNode
    private Incident createIncidentFromJsonNode(JsonNode jsonNode) {
        String sentinelId = jsonNode.get("name").asText();
        String title = jsonNode.get("properties").get("title").asText();
        String url = jsonNode.get("properties").get("incidentUrl").asText();

        String providerName = jsonNode.get("properties").get("providerName").asText();
        String providerIncidentId = jsonNode.get("properties").get("providerIncidentId").asText();
        Provider provider = Provider.builder().id(providerIncidentId).name(providerName).build();

        String severity = jsonNode.get("properties").get("severity").asText();

        return Incident.builder()
                .sentinelId(sentinelId)
                .title(title)
                .url(url)
                .provider(provider)
                .severity(severity)
                .build();
    }

}
