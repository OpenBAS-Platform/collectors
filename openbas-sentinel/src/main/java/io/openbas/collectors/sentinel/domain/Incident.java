package io.openbas.collectors.sentinel.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.List;

@Getter
@Setter
@Builder
public class Incident {

    private String sentinelId;
    private String title;
    private String url;
    private Provider provider;
    private String severity;
    private List<String> tactics;
    private List<String> techniques;
    private Instant createdTime;

}
