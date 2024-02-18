package io.openbas.collectors.sentinel.domain;

import lombok.Builder;

@Builder
public record Property(String label, String value) {}
