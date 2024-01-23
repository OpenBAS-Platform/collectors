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

    @Override
    public void run() {
        try {
            LOGGER.log(Level.INFO, "Starting collecting MITRE ATT&CK dataset...");
            JSONObject enterpriseAttack = getJson(new URI("https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"));
            JSONArray objects = enterpriseAttack.getJSONArray("objects");
            List<JSONObject> attackPatterns = new ArrayList<>();
            List<JSONObject> relationships = new ArrayList<>();
            for (int i = 0; i < objects.length(); i++) {
                JSONObject object = objects.getJSONObject(i);
                if (object.getString("type").equals("attack-pattern")) {
                    attackPatterns.add(object);
                } else if (object.getString("type").equals("relationship")) {
                    relationships.add(object);
                }
            }
            attackPatterns.forEach(jsonObject -> {
                // Get the kill chain
                JSONArray killChainPhases = jsonObject.getJSONArray("kill_chain_phases");
                for (int i = 0; i < killChainPhases.length(); i++) {
                    JSONObject killChain = killChainPhases.getJSONObject(i);
                    String killChainName = killChain.getString("kill_chain_name");
                    String phaseName = killChain.getString("phase_name");
                    KillChainPhase killChainPhase = killChainPhaseRepository.findKillChainPhaseByKillChainNameAndPhaseName(killChainName, phaseName);
                    if( killChainPhase == null ) {
                        killChainPhase = new KillChainPhase();
                        killChainPhase.setKillChainName(killChainName);
                        killChainPhase.setName(phaseName);
                        LOGGER.log(Level.INFO, "Creating kill chain phase [" + killChainName + "] " + phaseName);
                        killChainPhaseRepository.save(killChainPhase);
                    }
                }
                // Get the external references to extract the MITRE ID
                JSONArray externalReferences = jsonObject.getJSONArray("external_references");
                for (int i = 0; i < externalReferences.length(); i++) {
                    JSONObject externalReference = externalReferences.getJSONObject(i);
                    if (externalReference.getString("source_name").equals("mitre-attack").
                }

                String externalId = jsonObject.getString("name");

            });
        } catch (IOException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }
}
