package io.openbas.collectors.sentinel.application;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class SentinelJob implements Runnable {

  private final SentinelService sentinelService;

  @Override
  public void run() {
    this.sentinelService.computeDetectionExpectations();
  }

}
