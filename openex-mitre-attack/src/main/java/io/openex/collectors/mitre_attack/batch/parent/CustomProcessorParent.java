package io.openex.collectors.mitre_attack.batch.parent;

import io.openex.database.repository.AttackPatternRepository;
import org.json.JSONObject;
import org.springframework.batch.item.ItemProcessor;

public class CustomProcessorParent implements ItemProcessor<JSONObject, CustomProcessorParent.Parent> {

  private final AttackPatternRepository attackPatternRepository;

  public CustomProcessorParent(AttackPatternRepository attackPatternRepository) {
    this.attackPatternRepository = attackPatternRepository;
  }

  @Override
  public Parent process(final JSONObject jsonObject) {
    String parentAttackPatternRef = jsonObject.getString("target_ref");
    String childAttackPatternRef = jsonObject.getString("source_ref");
    String parentAttackPattern = attackPatternRepository.findIdByStixId(parentAttackPatternRef).orElseThrow();
    String childAttackPattern = attackPatternRepository.findIdByStixId(childAttackPatternRef).orElseThrow();
    return new Parent(parentAttackPattern, childAttackPattern);
  }

  public record Parent(String parentAttackPattern, String childAttackPattern) { }

}
