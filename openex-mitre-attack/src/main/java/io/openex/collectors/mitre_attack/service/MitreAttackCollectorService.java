package io.openex.collectors.mitre_attack.service;

import io.openex.database.model.AttackPattern;
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

import static io.openex.helper.StreamHelper.fromIterable;

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
            } else if (object.getString("type").equals("relationship") && object.getString("relationship_type").equals("subtechnique-of")) {
                relationships.add(object);
            }
        }
        // Sync kill chain phases
        List<KillChainPhase> killChainPhasesToSave = new ArrayList<>();
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

        // Sync attack patterns
        List<AttackPattern> attackPatternsToSave = new ArrayList<>();
        attackPatterns.forEach(jsonObject -> {
            String attackPatternStixId = jsonObject.getString("id");
            String attackPatternName = jsonObject.getString("name");
            String attackPatternDescription = jsonObject.getString("description");
            String[] attackPatternPlatforms = new String[0];
            if (jsonObject.has("x_mitre_platforms")) {
                attackPatternPlatforms = fromIterable(jsonObject.getJSONArray("x_mitre_platforms")).stream().map(Object::toString).toList().toArray(new String[0]);
            }
            String[] attackPatternPermissionsRequired = new String[0];
            if (jsonObject.has("x_mitre_permissions_required")) {
                attackPatternPermissionsRequired = fromIterable(jsonObject.getJSONArray("x_mitre_permissions_required")).stream().map(Object::toString).toList().toArray(new String[0]);
            }
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
            Optional<AttackPattern> optionalAttackPattern = attackPatternRepository.findByExternalId(attackPatternExternalId);
            if (optionalAttackPattern.isEmpty()) {
                AttackPattern newAttackPattern = new AttackPattern();
                newAttackPattern.setStixId(attackPatternStixId);
                newAttackPattern.setExternalId(attackPatternExternalId);
                newAttackPattern.setKillChainPhases(resolvedKillChainPhases);
                newAttackPattern.setName(attackPatternName);
                newAttackPattern.setDescription(attackPatternDescription);
                newAttackPattern.setPlatforms(attackPatternPlatforms);
                newAttackPattern.setPermissionsRequired(attackPatternPermissionsRequired);
                LOGGER.log(Level.INFO, "Creating attack pattern [" + killChainName + "][" + attackPatternExternalId + "] " + attackPatternName);
                attackPatternRepository.save(newAttackPattern);
            } else {
                AttackPattern attackPattern = optionalAttackPattern.get();
                attackPattern.setStixId(attackPatternStixId);
                attackPattern.setKillChainPhases(resolvedKillChainPhases);
                attackPattern.setName(attackPatternName);
                attackPattern.setDescription(attackPatternDescription);
                attackPattern.setPlatforms(attackPatternPlatforms);
                attackPattern.setPermissionsRequired(attackPatternPermissionsRequired);
                LOGGER.log(Level.INFO, "Updating attack pattern [" + killChainName + "][" + attackPatternExternalId + "] " + attackPatternName);
                attackPatternRepository.save(attackPattern);
            }
        });

        // Sync relationships
        List<AttackPattern> attackPatternsParenthoodToSave = new ArrayList<>();
        relationships.forEach(jsonObject -> {
            String parentAttackPatternRef = jsonObject.getString("target_ref");
            String childAttackPatternRef = jsonObject.getString("source_ref");
            AttackPattern parentAttackPattern = attackPatternRepository.findByStixId(parentAttackPatternRef).orElseThrow();
            AttackPattern childAttackPattern = attackPatternRepository.findByStixId(childAttackPatternRef).orElseThrow();
            childAttackPattern.setParent(parentAttackPattern);
            attackPatternRepository.save(childAttackPattern);
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
