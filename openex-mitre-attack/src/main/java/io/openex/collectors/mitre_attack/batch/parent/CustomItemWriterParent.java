package io.openex.collectors.mitre_attack.batch.parent;

import org.springframework.batch.item.database.BeanPropertyItemSqlParameterSourceProvider;
import org.springframework.batch.item.database.JdbcBatchItemWriter;
import org.springframework.batch.item.database.builder.JdbcBatchItemWriterBuilder;

import javax.sql.DataSource;

public class CustomItemWriterParent extends JdbcBatchItemWriter<CustomProcessorParent.Parent> {

  private final DataSource dataSource;

  public CustomItemWriterParent(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  public JdbcBatchItemWriter<CustomProcessorParent.Parent> build() {
    return new JdbcBatchItemWriterBuilder<CustomProcessorParent.Parent>()
        .itemSqlParameterSourceProvider(new BeanPropertyItemSqlParameterSourceProvider<>())
        .sql("UPDATE attack_patterns SET "
            + "attack_pattern_parent = ? "
            + "WHERE attack_pattern_id = ?")
        .itemPreparedStatementSetter((item, ps) -> {
          ps.setString(1, item.parentAttackPattern());
          ps.setString(2, item.childAttackPattern());
        })
        .dataSource(dataSource)
        .build();
  }
}
