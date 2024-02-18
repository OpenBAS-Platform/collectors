package io.openbas.collectors.sentinel.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Builder
public class ListOfIncidents {

    private List<Incident> incidents;

}
