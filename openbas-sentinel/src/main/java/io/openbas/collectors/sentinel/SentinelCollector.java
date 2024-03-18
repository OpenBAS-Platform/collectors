package io.openbas.collectors.sentinel;

import io.openbas.collectors.sentinel.service.LogAnalyticsService;
import io.openbas.collectors.sentinel.service.SentinelService;
import io.openbas.collectors.sentinel.config.CollectorSentinelConfig;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.stereotype.Service;

import java.time.Duration;

@RequiredArgsConstructor
@Service
@ConditionalOnProperty(prefix = "collector.sentinel", name = "enable")
public class SentinelCollector {

  private final CollectorSentinelConfig config;
  private final TaskScheduler taskScheduler;
  private final SentinelService sentinelService;
  private final LogAnalyticsService logAnalyticsService;

  @PostConstruct
  public void init() {
    // If enabled, scheduled every X seconds
    if (this.config.isEnable()) {
      SentinelJob job = new SentinelJob(this.sentinelService, this.logAnalyticsService);
      this.taskScheduler.scheduleAtFixedRate(job, Duration.ofSeconds(this.config.getInterval()));
    }
  }

}
