package io.openex.collectors.sentinel.application;

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
