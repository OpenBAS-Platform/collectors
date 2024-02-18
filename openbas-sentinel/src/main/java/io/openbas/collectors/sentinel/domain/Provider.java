package io.openbas.collectors.sentinel.domain;

import lombok.Builder;

@Builder
public record Provider(String id, String name) {}
