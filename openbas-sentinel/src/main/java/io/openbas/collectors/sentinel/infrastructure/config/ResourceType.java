package io.openbas.collectors.sentinel.infrastructure.config;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public enum ResourceType {

    ACTIONS ("actions"),
    ALERTS ("alerts"),
    ALERT_RULES ("alertRules"),
    API_VERSION ("api-version"),
    BOOKMARKS ("bookmarks"),
    EXPAND ("expand"),
    FILTER ("filter"),
    ENTITIES ("entities"),
    INCIDENTS ("incidents"),
    METADATA ("metadata"),
    RELATIONS ("relations");

   @Getter
    private String param;
}
