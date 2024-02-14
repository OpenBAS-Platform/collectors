package io.openbas.collectors.sentinel;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public enum ResourceType {

    ALERTS ("alerts"),
    ALERT_RULES ("alertRules"),
    API_VERSION ("api-version"),
    BOOKMARKS ("bookmarks"),
    FILTER ("filter"),
    ENTITIES ("entities"),
    INCIDENTS ("incidents"),
    METADATA ("metadata"),
    RELATIONS ("relations");

   @Getter
    private String param;
}
