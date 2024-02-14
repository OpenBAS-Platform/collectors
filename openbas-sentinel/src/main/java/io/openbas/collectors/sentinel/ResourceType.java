package io.openbas.collectors.sentinel;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public enum ResourceType {

    ALERT_RULES ("alertRules"),
    API_VERSION ("api-version"),
    INCIDENTS ("incidents"),
    INCIDENT_ID ("incidentId"),
    FILTER ("filter"),
    RELATIONS ("relations");

   @Getter
    private String param;
}
