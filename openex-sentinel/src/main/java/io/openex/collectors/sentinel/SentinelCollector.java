package io.openex.collectors.sentinel;

import io.openex.collectors.sentinel.application.SentinelJob;
import io.openex.collectors.sentinel.application.SentinelService;
import io.openex.collectors.sentinel.infrastructure.config.AuthenticationProperties;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.stereotype.Service;

import java.time.Duration;

@RequiredArgsConstructor
@Service
public class SentinelCollector {

  private final AuthenticationProperties config;
  private final TaskScheduler taskScheduler;
  private final SentinelService sentinelService;

  @PostConstruct
  public void init() {
    // If enabled, scheduled every X seconds
    if (this.config.isEnable()) {
      SentinelJob job = new SentinelJob(this.sentinelService);
      this.taskScheduler.scheduleAtFixedRate(job, Duration.ofSeconds(this.config.getInterval()));
    }
  }

}
