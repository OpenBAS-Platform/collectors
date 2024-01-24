package io.openex.collectors.mitre_attack.batch.relationship;

import io.openex.database.model.AttackPattern;
import org.springframework.batch.item.database.BeanPropertyItemSqlParameterSourceProvider;
import org.springframework.batch.item.database.JdbcBatchItemWriter;
import org.springframework.batch.item.database.builder.JdbcBatchItemWriterBuilder;

import javax.sql.DataSource;
import java.sql.SQLException;

public class CustomItemWriterRelationship extends JdbcBatchItemWriter<AttackPattern> {

  private final DataSource dataSource;

  public CustomItemWriterRelationship(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  public JdbcBatchItemWriter<AttackPattern> build() {
    return new JdbcBatchItemWriterBuilder<AttackPattern>()
        .itemSqlParameterSourceProvider(new BeanPropertyItemSqlParameterSourceProvider<>())
        .sql("DELETE FROM attack_patterns_kill_chain_phases "
            + "WHERE attack_pattern_id = ? ")
        .itemPreparedStatementSetter((item, ps) -> {
          ps.setString(1, item.getId());
        })
        .sql("INSERT INTO attack_patterns_kill_chain_phases "
            + "(attack_pattern_id, phase_id) "
            + "VALUES (?, ?) "
            + "ON CONFLICT (attack_pattern_id, phase_id) DO UPDATE SET"
            + "  attack_pattern_id = ?,"
            + "  phase_id = ?"
        )
        .itemPreparedStatementSetter((item, ps) -> {
          item.getKillChainPhases().forEach((k) -> {
            try {
              ps.setString(1, item.getId());
              ps.setString(2, k.getId());
              ps.setString(3, item.getId());
              ps.setString(4, k.getId());
            } catch (SQLException e) {
              throw new RuntimeException(e);
            }
          });
        })
        .dataSource(dataSource)
        .build();
  }
}
