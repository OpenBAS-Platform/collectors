package io.openex.collectors.mitre_attack.service;

import io.openex.database.model.KillChainPhase;
import io.openex.database.repository.AttackPatternRepository;
import io.openex.database.repository.KillChainPhaseRepository;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MitreAttackCollectorService implements Runnable {
    private static final Logger LOGGER = Logger.getLogger(MitreAttackCollectorService.class.getName());
    private final KillChainPhaseRepository killChainPhaseRepository;

    private final AttackPatternRepository attackPatternRepository;

    public MitreAttackCollectorService(KillChainPhaseRepository killChainPhaseRepository, AttackPatternRepository attackPatternRepository) {
        this.killChainPhaseRepository = killChainPhaseRepository;
        this.attackPatternRepository = attackPatternRepository;
    }

    public static JSONObject getJson(URI url) throws IOException {
        String json = IOUtils.toString(url, StandardCharsets.UTF_8);
        return new JSONObject(json);
    }

    public void processBundle(String killChainName, JSONObject bundle) {
        JSONArray objects = bundle.getJSONArray("objects");
        List<JSONObject> tactics = new ArrayList<>();
        List<JSONObject> attackPatterns = new ArrayList<>();
        List<JSONObject> relationships = new ArrayList<>();
        for (int i = 0; i < objects.length(); i++) {
            JSONObject object = objects.getJSONObject(i);
            if (object.getString("type").equals("attack-pattern")) {
                attackPatterns.add(object);
            } else if (object.getString("type").equals("x-mitre-tactic")) {
                tactics.add(object);
            } else if (object.getString("type").equals("relationship")) {
                relationships.add(object);
            }
        }
        tactics.forEach(jsonObject -> {
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
            Optional<KillChainPhase> optionalKillChainPhase = killChainPhaseRepository.findByKillChainNameAndShortName(killChainName, phaseShortName);
            if (optionalKillChainPhase.isEmpty()) {
                KillChainPhase newKillChainPhase = new KillChainPhase();
                newKillChainPhase.setKillChainName(killChainName);
                newKillChainPhase.setStixId(phaseStixId);
                newKillChainPhase.setExternalId(phaseExternalId);
                newKillChainPhase.setShortName(phaseShortName);
                newKillChainPhase.setName(phaseName);
                newKillChainPhase.setDescription(phaseDescripion);
                LOGGER.log(Level.INFO, "Creating kill chain phase [" + killChainName + "] " + phaseName);
                killChainPhaseRepository.save(newKillChainPhase);
            } else {
                KillChainPhase killChainPhase = optionalKillChainPhase.get();
                killChainPhase.setStixId(phaseStixId);
                killChainPhase.setShortName(phaseShortName);
                killChainPhase.setName(phaseName);
                killChainPhase.setExternalId(phaseExternalId);
                killChainPhase.setDescription(phaseDescripion);
                LOGGER.log(Level.INFO, "Updating kill chain phase [" + killChainName + "] " + phaseName);
                killChainPhaseRepository.save(killChainPhase);
            }
        });
        attackPatterns.forEach(jsonObject -> {
            // Get the kill chain
            JSONArray killChainPhases = jsonObject.getJSONArray("kill_chain_phases");
            List<KillChainPhase> resolvedKillChainPhases = new ArrayList<>();
            for (int i = 0; i < killChainPhases.length(); i++) {
                JSONObject killChain = killChainPhases.getJSONObject(i);
                String phaseShortName = killChain.getString("phase_name");
                KillChainPhase killChainPhase = killChainPhaseRepository.findByKillChainNameAndShortName(killChainName, phaseShortName).orElseThrow();
                resolvedKillChainPhases.add(killChainPhase);
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
        });
    }

    @Override
    public void run() {
        try {
            LOGGER.log(Level.INFO, "Starting collecting MITRE ATT&CK dataset...");
            JSONObject enterpriseAttack = getJson(new URI("https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"));
            this.processBundle("mitre-attack", enterpriseAttack);
        } catch (IOException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }
}
