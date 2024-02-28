package io.openex.collectors.sentinel.infrastructure.config;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
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
  FILTER_UPDATED_SINCE_GREATER_THAN("$filter=properties/lastModifiedTimeUtc gt "),
  GREATER_THAN ("gt"),
  INCIDENTS ("incidents"),
  LESS_THAN ("lg"),
  METADATA ("metadata"),
  RELATIONS ("relations");

  private final String param;
}
