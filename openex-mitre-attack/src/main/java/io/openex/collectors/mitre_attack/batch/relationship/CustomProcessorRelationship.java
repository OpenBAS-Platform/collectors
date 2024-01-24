package io.openex.collectors.mitre_attack.batch.relationship;

import io.openex.database.model.AttackPattern;
import io.openex.database.model.KillChainPhase;
import io.openex.database.repository.AttackPatternRepository;
import io.openex.database.repository.KillChainPhaseRepository;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.batch.item.ItemProcessor;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static io.openex.collectors.mitre_attack.batch.SpringBatchScheduler.KILL_CHAIN_NAME;

public class CustomProcessorRelationship implements ItemProcessor<JSONObject, AttackPattern> {

  private final KillChainPhaseRepository killChainPhaseRepository;
  private final AttackPatternRepository attackPatternRepository;

  public CustomProcessorRelationship(
      KillChainPhaseRepository killChainPhaseRepository,
      AttackPatternRepository attackPatternRepository) {
    this.killChainPhaseRepository = killChainPhaseRepository;
    this.attackPatternRepository = attackPatternRepository;
  }

  @Override
  public AttackPattern process(final JSONObject jsonObject) {
    // Get the external references to extract the MITRE ID
    String attackPatternExternalId = "";
    JSONArray externalReferences = jsonObject.getJSONArray("external_references");
    for (int i = 0; i < externalReferences.length(); i++) {
      JSONObject externalReference = externalReferences.getJSONObject(i);
      if (externalReference.getString("source_name").equals("mitre-attack")) {
        attackPatternExternalId = externalReference.getString("external_id");
      }
    }

    AttackPattern attackPattern = attackPatternRepository.findByExternalId(attackPatternExternalId).orElseThrow();
    // Get the kill chain
    JSONArray killChainPhases = jsonObject.getJSONArray("kill_chain_phases");
    List<KillChainPhase> resolvedKillChainPhases = new ArrayList<>();
    for (int i = 0; i < killChainPhases.length(); i++) {
      JSONObject killChain = killChainPhases.getJSONObject(i);
      String phaseShortName = killChain.getString("phase_name");
      Optional<KillChainPhase> killChainPhase = killChainPhaseRepository
          .findByKillChainNameAndShortName(KILL_CHAIN_NAME, phaseShortName);
      killChainPhase.ifPresent(resolvedKillChainPhases::add);
    }
    attackPattern.setKillChainPhases(resolvedKillChainPhases);
    return attackPattern;
  }

}
