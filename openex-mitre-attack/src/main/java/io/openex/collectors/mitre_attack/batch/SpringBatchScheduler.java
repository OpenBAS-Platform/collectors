package io.openex.collectors.mitre_attack.batch;


import io.openex.collectors.mitre_attack.batch.attack_pattern.CustomItemReaderAttackPattern;
import io.openex.collectors.mitre_attack.batch.attack_pattern.CustomItemWriterAttackPattern;
import io.openex.collectors.mitre_attack.batch.attack_pattern.CustomProcessorAttackPattern;
import io.openex.collectors.mitre_attack.batch.kill_chain_phase.CustomItemReaderKillChainPhases;
import io.openex.collectors.mitre_attack.batch.kill_chain_phase.CustomItemWriterKillChainPhase;
import io.openex.collectors.mitre_attack.batch.kill_chain_phase.CustomProcessorKillChainPhase;
import io.openex.collectors.mitre_attack.batch.parent.CustomItemReaderParent;
import io.openex.collectors.mitre_attack.batch.parent.CustomItemWriterParent;
import io.openex.collectors.mitre_attack.batch.parent.CustomProcessorParent;
import io.openex.collectors.mitre_attack.batch.relationship.CustomItemReaderRelationship;
import io.openex.collectors.mitre_attack.batch.relationship.CustomItemWriterRelationship;
import io.openex.collectors.mitre_attack.batch.relationship.CustomProcessorRelationship;
import io.openex.database.model.AttackPattern;
import io.openex.database.model.KillChainPhase;
import io.openex.database.repository.AttackPatternRepository;
import io.openex.database.repository.KillChainPhaseRepository;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.JobParametersBuilder;
import org.springframework.batch.core.Step;
import org.springframework.batch.core.job.builder.JobBuilder;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.batch.core.repository.JobRepository;
import org.springframework.batch.core.step.builder.StepBuilder;
import org.springframework.batch.item.database.JdbcBatchItemWriter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

@ConditionalOnProperty(prefix = "collector", name = "mitre-attack.enable")
@Configuration
@Slf4j
public class SpringBatchScheduler {

  public static final String KILL_CHAIN_NAME = "mitre-attack";


  private AtomicInteger batchRunCounter = new AtomicInteger(0);

  private final JobLauncher jobLauncher;
  private final JobRepository jobRepository;
  private final PlatformTransactionManager transactionManager;
  private final DataSource dataSource;

  private final KillChainPhaseRepository killChainPhaseRepository;
  private final AttackPatternRepository attackPatternRepository;

  private JSONArray objects;

  public SpringBatchScheduler(
      JobLauncher jobLauncher,
      JobRepository jobRepository,
      PlatformTransactionManager transactionManager,
      DataSource dataSource,
      KillChainPhaseRepository killChainPhaseRepository,
      AttackPatternRepository attackPatternRepository) {
    this.jobLauncher = jobLauncher;
    this.jobRepository = jobRepository;
    this.transactionManager = transactionManager;
    this.dataSource = dataSource;
    this.killChainPhaseRepository = killChainPhaseRepository;
    this.attackPatternRepository = attackPatternRepository;
    // Resolve bundle to process
    try {
      JSONObject bundle = getJson(
          new URI("https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"));
      this.objects = bundle.getJSONArray("objects");
    } catch (IOException | URISyntaxException e) {
      throw new RuntimeException(e);
    }
  }

  @Scheduled(fixedDelayString = "36000")
  public void launchJob() throws Exception {
    Date date = new Date();
    log.debug("scheduler starts at " + date);
    JobExecution jobExecution = jobLauncher.run(job(jobRepository, transactionManager),
        new JobParametersBuilder().addDate("launchDate", date)
            .toJobParameters());
    batchRunCounter.incrementAndGet();
    log.debug("Batch job ends with status as " + jobExecution.getStatus());
    log.debug("scheduler ends ");
  }

  public static org.json.JSONObject getJson(URI url) throws IOException {
    String json = IOUtils.toString(url, StandardCharsets.UTF_8);
    return new org.json.JSONObject(json);
  }

  @Bean
  public Job job(JobRepository jobRepository, PlatformTransactionManager transactionManager) {
    return new JobBuilder("mitreAttackJob", jobRepository)
        .start(readKillChainPhase(jobRepository, transactionManager))
        .next(readAttackPattern(jobRepository, transactionManager))
        .next(readLink(jobRepository, transactionManager))
        .next(readParent(jobRepository, transactionManager))
        .build();
  }

  // -- KILL CHAIN PHASES --

  @Bean
  protected Step readKillChainPhase(JobRepository jobRepository, PlatformTransactionManager transactionManager) {
    return new StepBuilder("killChainPhases", jobRepository)
        .<JSONObject, KillChainPhase>chunk(10, transactionManager)
        .reader(readerKillChainPhases())
        .processor(processorKillChainPhases())
        .writer(writerKillChainPhases())
        .build();
  }

  @Bean
  public CustomItemReaderKillChainPhases readerKillChainPhases() {
    return new CustomItemReaderKillChainPhases(this.objects);
  }

  // Sync kill chain phases
  @Bean
  public CustomProcessorKillChainPhase processorKillChainPhases() {
    return new CustomProcessorKillChainPhase(killChainPhaseRepository);
  }

  @Bean
  public JdbcBatchItemWriter<KillChainPhase> writerKillChainPhases() {
    return new CustomItemWriterKillChainPhase(this.dataSource).build();
  }

  // -- ATTACK PATTERN --

  @Bean
  protected Step readAttackPattern(JobRepository jobRepository, PlatformTransactionManager transactionManager) {
    return new StepBuilder("attackPatterns", jobRepository)
        .<JSONObject, AttackPattern>chunk(10, transactionManager)
        .reader(readerAttackPattern())
        .processor(processorAttackPattern())
        .writer(writerAttackPattern())
        .build();
  }

  @Bean
  public CustomItemReaderAttackPattern readerAttackPattern() {
    return new CustomItemReaderAttackPattern(this.objects);
  }

  @Bean
  public CustomProcessorAttackPattern processorAttackPattern() {
    return new CustomProcessorAttackPattern(attackPatternRepository);
  }

  @Bean
  public JdbcBatchItemWriter<AttackPattern> writerAttackPattern() {
    return new CustomItemWriterAttackPattern(this.dataSource).build();
  }

  // -- LINK --

  @Bean
  protected Step readLink(JobRepository jobRepository, PlatformTransactionManager transactionManager) {
    return new StepBuilder("links", jobRepository)
        .<JSONObject, AttackPattern>chunk(10, transactionManager)
        .reader(readerLink())
        .processor(processorLinks())
        .writer(writerLinks())
        .build();
  }

  @Bean
  public CustomItemReaderRelationship readerLink() {
    return new CustomItemReaderRelationship(this.objects);
  }

  @Bean
  public CustomProcessorRelationship processorLinks() {
    return new CustomProcessorRelationship(killChainPhaseRepository, attackPatternRepository);
  }

  @Bean
  public JdbcBatchItemWriter<AttackPattern> writerLinks() {
    return new CustomItemWriterRelationship(this.dataSource).build();
  }

  // -- PARENT --

  @Bean
  protected Step readParent(JobRepository jobRepository, PlatformTransactionManager transactionManager) {
    return new StepBuilder("parents", jobRepository)
        .<JSONObject, CustomProcessorParent.Parent>chunk(10, transactionManager)
        .reader(readerParents())
        .processor(processorParents())
        .writer(writerParents())
        .build();
  }

  @Bean
  public CustomItemReaderParent readerParents() {
    return new CustomItemReaderParent(this.objects);
  }

  @Bean
  public CustomProcessorParent processorParents() {
    return new CustomProcessorParent(attackPatternRepository);
  }

  @Bean
  public JdbcBatchItemWriter<CustomProcessorParent.Parent> writerParents() {
    return new CustomItemWriterParent(this.dataSource).build();
  }

}
