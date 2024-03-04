package io.openbas.collectors.sentinel;

import io.openbas.collectors.sentinel.service.LogAnalyticsService;
import io.openbas.collectors.sentinel.service.SentinelService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
@ConditionalOnProperty(prefix = "collector.sentinel", name = "enable")
public class SentinelJob implements Runnable {

  private final SentinelService sentinelService;
  private final LogAnalyticsService logAnalyticsService;

  @Override
  public void run() {
    // Detection
    this.sentinelService.computeDetectionExpectations();
    // Prevention
    this.logAnalyticsService.computePreventionExpectations();
  }

}
