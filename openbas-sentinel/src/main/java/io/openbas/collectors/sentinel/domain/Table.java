package io.openbas.collectors.sentinel.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.LinkedHashMap;
import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class Table {

  private String name;
  private List<Column> columns;
  private List<List<String>> rows;

  public static String getHostName(LinkedHashMap<String, Object> entities) {
    return (String) entities.get("HostName");
  }

  public static String getCommandLine(LinkedHashMap<String, Object> entities) {
    return (String) entities.get("CommandLine");
  }

}
