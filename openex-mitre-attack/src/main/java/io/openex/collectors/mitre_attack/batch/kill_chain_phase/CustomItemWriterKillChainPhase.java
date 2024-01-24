package io.openex.collectors.mitre_attack.batch.kill_chain_phase;

import io.openex.database.model.KillChainPhase;
import org.springframework.batch.item.database.BeanPropertyItemSqlParameterSourceProvider;
import org.springframework.batch.item.database.JdbcBatchItemWriter;
import org.springframework.batch.item.database.builder.JdbcBatchItemWriterBuilder;

import javax.sql.DataSource;
import java.sql.Timestamp;

public class CustomItemWriterKillChainPhase extends JdbcBatchItemWriter<KillChainPhase> {

  private final DataSource dataSource;

  public CustomItemWriterKillChainPhase(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  public JdbcBatchItemWriter<KillChainPhase> build() {
    return new JdbcBatchItemWriterBuilder<KillChainPhase>()
        .itemSqlParameterSourceProvider(new BeanPropertyItemSqlParameterSourceProvider<>())
        .sql(
            "INSERT INTO kill_chain_phases "
                + "(phase_id, phase_external_id, phase_stix_id, phase_name, "
                + "phase_shortname, phase_kill_chain_name, phase_description, "
                + "phase_order, phase_created_at, phase_updated_at) "
                + "VALUES "
                + "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                + " ON CONFLICT (phase_kill_chain_name, phase_name) DO UPDATE SET "
                + "phase_external_id = ?, "
                + "phase_stix_id = ?, "
                + "phase_name = ?, "
                + "phase_shortname = ?, "
                + "phase_description = ?, "
                + "phase_updated_at = ?"
        )
        .itemPreparedStatementSetter((item, ps) -> {
          // create
          ps.setString(1, item.getId());
          ps.setString(2, item.getExternalId());
          ps.setString(3, item.getStixId());
          ps.setString(4, item.getName());
          ps.setString(5, item.getShortName());
          ps.setString(6, item.getKillChainName());
          ps.setString(7, item.getDescription());
          ps.setLong(8, item.getOrder());
          ps.setTimestamp(9, Timestamp.from(item.getCreatedAt()));
          ps.setTimestamp(10, Timestamp.from(item.getUpdatedAt()));
          // update
          ps.setString(11, item.getExternalId());
          ps.setString(12, item.getStixId());
          ps.setString(13, item.getName());
          ps.setString(14, item.getShortName());
          ps.setString(15, item.getDescription());
          ps.setTimestamp(16, Timestamp.from(item.getUpdatedAt()));
        })
        .dataSource(dataSource)
        .build();
  }
}
