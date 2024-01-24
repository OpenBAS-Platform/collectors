package io.openex.collectors.mitre_attack.batch.attack_pattern;

import io.openex.database.model.AttackPattern;
import org.springframework.batch.item.database.BeanPropertyItemSqlParameterSourceProvider;
import org.springframework.batch.item.database.JdbcBatchItemWriter;
import org.springframework.batch.item.database.builder.JdbcBatchItemWriterBuilder;

import javax.sql.DataSource;
import java.sql.Timestamp;

public class CustomItemWriterAttackPattern extends JdbcBatchItemWriter<AttackPattern> {

  private final DataSource dataSource;

  public CustomItemWriterAttackPattern(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  public JdbcBatchItemWriter<AttackPattern> build() {
    return new JdbcBatchItemWriterBuilder<AttackPattern>()
        .itemSqlParameterSourceProvider(new BeanPropertyItemSqlParameterSourceProvider<>())
        .sql(
            "INSERT INTO attack_patterns "
                + "(attack_pattern_id, attack_pattern_stix_id, attack_pattern_name, attack_pattern_description, "
                + "attack_pattern_external_id, attack_pattern_platforms, attack_pattern_permissions_required, "
                + "attack_pattern_created_at, attack_pattern_updated_at) "
                + "VALUES "
                + "(?, ?, ?, ?, ?, ?, ?, ?, ?)"
                + " ON CONFLICT (attack_pattern_id) DO UPDATE SET "
                + "attack_pattern_stix_id = ?, "
                + "attack_pattern_name = ?, "
                + "attack_pattern_description = ?, "
                + "attack_pattern_platforms = ?, "
                + "attack_pattern_permissions_required = ?, "
                + "attack_pattern_updated_at = ? "
        )
        .itemPreparedStatementSetter((item, ps) -> {
          // create
          ps.setString(1, item.getId());
          ps.setString(2, item.getStixId());
          ps.setString(3, item.getName());
          ps.setString(4, item.getDescription());
          ps.setString(5, item.getExternalId());
          ps.setArray(6, ps.getConnection().createArrayOf("text", item.getPlatforms()));
          ps.setArray(7, ps.getConnection().createArrayOf("text", item.getPermissionsRequired()));
          ps.setTimestamp(8, Timestamp.from(item.getCreatedAt()));
          ps.setTimestamp(9, Timestamp.from(item.getUpdatedAt()));
          // update
          ps.setString(10, item.getStixId());
          ps.setString(11, item.getName());
          ps.setString(12, item.getDescription());
          ps.setArray(13, ps.getConnection().createArrayOf("text", item.getPlatforms()));
          ps.setArray(14, ps.getConnection().createArrayOf("text", item.getPermissionsRequired()));
          ps.setTimestamp(15, Timestamp.from(item.getUpdatedAt()));
        })
        .dataSource(dataSource)
        .build();
  }
}
