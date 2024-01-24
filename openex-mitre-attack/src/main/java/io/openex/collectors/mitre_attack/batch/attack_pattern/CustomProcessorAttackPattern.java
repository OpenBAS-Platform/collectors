package io.openex.collectors.mitre_attack.batch.attack_pattern;

import io.openex.database.model.AttackPattern;
import io.openex.database.repository.AttackPatternRepository;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.batch.item.ItemProcessor;

import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.openex.collectors.mitre_attack.batch.SpringBatchScheduler.KILL_CHAIN_NAME;
import static io.openex.helper.StreamHelper.fromIterable;

public class CustomProcessorAttackPattern implements ItemProcessor<JSONObject, AttackPattern> {
  private static final Logger LOGGER = Logger.getLogger(CustomProcessorAttackPattern.class.getName());
  private final AttackPatternRepository attackPatternRepository;

  public CustomProcessorAttackPattern(AttackPatternRepository attackPatternRepository) {
    this.attackPatternRepository = attackPatternRepository;
  }

  @Override
  public AttackPattern process(final JSONObject jsonObject) {
    String attackPatternStixId = jsonObject.getString("id");
    String attackPatternName = jsonObject.getString("name");
    String attackPatternDescription = jsonObject.getString("description");
    String[] attackPatternPlatforms = new String[0];
    if (jsonObject.has("x_mitre_platforms")) {
      attackPatternPlatforms = fromIterable(jsonObject.getJSONArray("x_mitre_platforms")).stream().map(Object::toString)
          .toList().toArray(new String[0]);
    }
    String[] attackPatternPermissionsRequired = new String[0];
    if (jsonObject.has("x_mitre_permissions_required")) {
      attackPatternPermissionsRequired = fromIterable(jsonObject.getJSONArray("x_mitre_permissions_required")).stream()
          .map(Object::toString).toList().toArray(new String[0]);
    }
    // Get the external references to extract the MITRE ID
    String attackPatternExternalId = "";
    JSONArray externalReferences = jsonObject.getJSONArray("external_references");
    for (int i = 0; i < externalReferences.length(); i++) {
      JSONObject externalReference = externalReferences.getJSONObject(i);
      if (externalReference.getString("source_name").equals("mitre-attack")) {
        attackPatternExternalId = externalReference.getString("external_id");
      }
    }
    Optional<String> optionalAttackPattern = attackPatternRepository.findId(attackPatternExternalId);
    if (optionalAttackPattern.isEmpty()) {
      AttackPattern newAttackPattern = new AttackPattern();
      newAttackPattern.setId(UUID.randomUUID().toString()); // Direct call to DB
      newAttackPattern.setStixId(attackPatternStixId);
      newAttackPattern.setName(attackPatternName);
      newAttackPattern.setDescription(attackPatternDescription);
      newAttackPattern.setExternalId(attackPatternExternalId);
      newAttackPattern.setPlatforms(attackPatternPlatforms);
      newAttackPattern.setPermissionsRequired(attackPatternPermissionsRequired);
      LOGGER.log(
          Level.INFO, "Creating attack pattern [" + KILL_CHAIN_NAME + "][" + attackPatternExternalId + "] " + attackPatternName);
      return newAttackPattern;
    } else {
      AttackPattern attackPattern = new AttackPattern();
      attackPattern.setId(optionalAttackPattern.get()); // Direct call to DB
      attackPattern.setStixId(attackPatternStixId);
      attackPattern.setName(attackPatternName);
      attackPattern.setDescription(attackPatternDescription);
      attackPattern.setExternalId(attackPatternExternalId);
      attackPattern.setPlatforms(attackPatternPlatforms);
      attackPattern.setPermissionsRequired(attackPatternPermissionsRequired);
      LOGGER.log(Level.INFO, "Updating attack pattern [" + KILL_CHAIN_NAME + "][" + attackPatternExternalId + "] " + attackPatternName);
      return attackPattern;
    }
  }

}
