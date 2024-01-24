package io.openex.collectors.mitre_attack.batch.kill_chain_phase;

import io.openex.database.model.KillChainPhase;
import io.openex.database.repository.KillChainPhaseRepository;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.batch.item.ItemProcessor;

import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import static io.openex.collectors.mitre_attack.batch.SpringBatchScheduler.KILL_CHAIN_NAME;

public class CustomProcessorKillChainPhase implements ItemProcessor<JSONObject, KillChainPhase> {
  private static final Logger LOGGER = Logger.getLogger(CustomProcessorKillChainPhase.class.getName());
  private final KillChainPhaseRepository killChainPhaseRepository;

  public CustomProcessorKillChainPhase(KillChainPhaseRepository killChainPhaseRepository) {
    this.killChainPhaseRepository = killChainPhaseRepository;
  }

  @Override
  public KillChainPhase process(final JSONObject jsonObject) {
    String phaseStixId = jsonObject.getString("id");
    String phaseShortName = jsonObject.getString("x_mitre_shortname");
    String phaseName = jsonObject.getString("name");
    String phaseDescripion = jsonObject.getString("description");
    // Get the external references to extract the MITRE ID
    String phaseExternalId = "";
    JSONArray externalReferences = jsonObject.getJSONArray("external_references");
    for (int i = 0; i < externalReferences.length(); i++) {
      JSONObject externalReference = externalReferences.getJSONObject(i);
      if (externalReference.getString("source_name").equals("mitre-attack")) {
        phaseExternalId = externalReference.getString("external_id");
      }
    }
    Optional<String> optionalKillChainPhase = killChainPhaseRepository
        .findIdByKillChainNameAndShortName(KILL_CHAIN_NAME, phaseShortName);
    if (optionalKillChainPhase.isEmpty()) {
      KillChainPhase newKillChainPhase = new KillChainPhase();
      newKillChainPhase.setId(UUID.randomUUID().toString()); // Direct call to DB
      newKillChainPhase.setExternalId(phaseExternalId);
      newKillChainPhase.setStixId(phaseStixId);
      newKillChainPhase.setName(phaseName);
      newKillChainPhase.setShortName(phaseShortName);
      newKillChainPhase.setKillChainName(KILL_CHAIN_NAME);
      newKillChainPhase.setDescription(phaseDescripion);
      LOGGER.log(Level.INFO, "Kill chain phase [" + KILL_CHAIN_NAME + "] " + phaseName);
      return newKillChainPhase;
    } else {
      KillChainPhase killChainPhase = new KillChainPhase();
      killChainPhase.setId(optionalKillChainPhase.get()); // Direct call to DB
      killChainPhase.setExternalId(phaseExternalId);
      killChainPhase.setStixId(phaseStixId);
      killChainPhase.setName(phaseName);
      killChainPhase.setShortName(phaseShortName);
      killChainPhase.setDescription(phaseDescripion);
      LOGGER.log(Level.INFO, "Updating kill chain phase [" + KILL_CHAIN_NAME + "] " + phaseName);
      return killChainPhase;
    }
  }

}
