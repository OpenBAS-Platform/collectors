package io.openbas.collectors.caldera;

import io.openbas.collectors.caldera.client.CollectorCalderaClient;
import io.openbas.collectors.caldera.config.CollectorCalderaConfig;
import io.openbas.collectors.caldera.service.CollectorCalderaService;
import io.openbas.asset.EndpointService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.stereotype.Service;

import java.time.Duration;

@RequiredArgsConstructor
@Service
public class CollectorCaldera {

  private final CollectorCalderaConfig config;
  private final TaskScheduler taskScheduler;
  private final CollectorCalderaClient client;
  private final EndpointService endpointService;

  @PostConstruct
  public void init() {
    // If enabled, scheduled every X seconds
    if (this.config.isEnable()) {
      CollectorCalderaService service = new CollectorCalderaService(this.client, this.config, this.endpointService);
      this.taskScheduler.scheduleAtFixedRate(service, Duration.ofSeconds(this.config.getInterval()));
    }
  }

}
