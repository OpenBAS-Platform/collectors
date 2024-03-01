package io.openbas.collectors.sentinel.application;

import io.openbas.collectors.sentinel.application.SentinelService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class SentinelServiceTest {

  @Autowired
  private SentinelService sentinelService;

  @Test
  void test() {
    this.sentinelService.computeDetectionExpectations();
  }

}
