package io.openbas.collectors.sentinel.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Builder
public class Entity {

    private final String sentinelId;
    private final String kind;
    private final List<Property> properties;

}
