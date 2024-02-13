package io.openbas.collectors.sentinel;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public enum ResourceType {

    ALERT_RULES ("alertRules"),
    INCIDENTS ("incidents"),
    API_VERSION ("api-version");

   @Getter
    private String param;

}
