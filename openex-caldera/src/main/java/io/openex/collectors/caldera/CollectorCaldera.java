package io.openex.collectors.caldera;

import io.openex.collectors.caldera.client.CollectorCalderaClient;
import io.openex.collectors.caldera.config.CollectorCalderaConfig;
import io.openex.collectors.caldera.service.CollectorCalderaService;
import io.openex.service.AssetEndpointService;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.time.Duration;

@RequiredArgsConstructor
@Service
public class CollectorCaldera {

  private final CollectorCalderaConfig config;
  private final TaskScheduler taskScheduler;
  private final CollectorCalderaClient client;
  private final AssetEndpointService assetEndpointService;

  @PostConstruct
  public void init() {
    // If enabled, scheduled every 60 seconds
    if (this.config.isEnable()) {
      CollectorCalderaService service = new CollectorCalderaService(this.client, this.assetEndpointService);
      this.taskScheduler.scheduleAtFixedRate(service, Duration.ofSeconds(this.config.getInterval()));
    }
  }

}
