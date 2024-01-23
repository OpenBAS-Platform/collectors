package io.openex.collectors.mitre_attack;

import io.openex.collectors.mitre_attack.config.MitreAttackCollectorConfig;
import io.openex.collectors.mitre_attack.service.MitreAttackCollectorService;
import io.openex.database.repository.KillChainPhaseRepository;
import io.openex.database.repository.AttackPatternRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.util.Optional;

@Component
public class MitreAttackCollector {

    private MitreAttackCollectorConfig mitreAttackCollectorConfig;

    private TaskScheduler taskScheduler;

    private KillChainPhaseRepository killChainPhaseRepository;

    private AttackPatternRepository attackPatternRepository;

    @Autowired
    public void setMitreAttackCollectorConfig(MitreAttackCollectorConfig mitreAttackCollectorConfig) {
        this.mitreAttackCollectorConfig = mitreAttackCollectorConfig;
    }

    @Autowired
    public void setKillChainPhaseRepository(KillChainPhaseRepository killChainPhaseRepository) {
        this.killChainPhaseRepository = killChainPhaseRepository;
    }

    @Autowired
    public void setAttackPatternRepository(AttackPatternRepository attackPatternRepository) {
        this.attackPatternRepository = attackPatternRepository;
    }

    @Autowired
    public void setTaskScheduler(TaskScheduler taskScheduler) {
        this.taskScheduler = taskScheduler;
    }

    @PostConstruct
    public void init() {
        // If enabled, scheduled every 5 seconds
        if (Optional.ofNullable(mitreAttackCollectorConfig.getEnable()).orElse(false)) {
            MitreAttackCollectorService task = new MitreAttackCollectorService(killChainPhaseRepository, attackPatternRepository);
            taskScheduler.scheduleAtFixedRate(task, Duration.ofSeconds(3600));
        }
    }
}
