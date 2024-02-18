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
    ENTITIES ("entities"),
    FILTER ("$filter"),
    FILTER_CREATED_SINCE_GREATER_THAN("$filter=properties/createdTimeUtc gt "),
    GREATER_THAN ("gt"),
    INCIDENTS ("incidents"),
    LESS_THAN ("lg"),
    METADATA ("metadata"),
    RELATIONS ("relations");

   @Getter
    private String param;
}
