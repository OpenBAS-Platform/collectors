import requests
from pybas import OpenBAS
from pybas._injectors.injector_helper import OpenBASCollectorHelper

ENTERPRISE_ATTACK_URI = (
    "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
)


class OpenBASMitre:
    def __init__(self):
        self.session = requests.Session()
        config = {
            "collector_id": "ba0003bc-4edc-45f3-b047-bda6c3b66f78",
            "collector_name": "Http injector",
        }
        injector_config = {
            "connection": {
                "host": "192.168.2.36",
                "vhost": "/",
                "use_ssl": False,
                "port": 5672,
                "user": "guest",
                "pass": "guest",
            }
        }
        self.client = OpenBAS(
            url="http://localhost:3001/api",
            token="3207fa04-35d8-4baa-a735-17033abf101d",
        )
        self.helper = OpenBASCollectorHelper(self.client, config, injector_config)

    def _kill_chain_phases(self, tactics):
        kill_chain_name = "mitre-attack"
        kill_chain_phases = []
        for tactic in tactics:
            phase_stix_id = tactic.get("id")
            phase_shortname = tactic.get("x_mitre_shortname")
            phase_name = tactic.get("name")
            phase_description = tactic.get("description")
            phase_external_id = ""
            external_references = tactic.get("external_references")
            for external_reference in external_references:
                if external_reference.get("source_name") == "mitre-attack":
                    phase_external_id = external_reference.get("external_id")
            kill_chain_phase = {
                "phase_kill_chain_name": kill_chain_name,
                "phase_stix_id": phase_stix_id,
                "phase_external_id": phase_external_id,
                "phase_short_name": phase_shortname,
                "phase_name": phase_name,
                "phase_description": phase_description,
            }
            kill_chain_phases.append(kill_chain_phase)
        self.client.kill_chain_phase.upsert(kill_chain_phases)

    def _attack_patterns(self, attacks):
        attack_patterns = []
        for attack in attacks:
            stix_id = attack.get("id")
            attack_pattern_name = attack.get("name")
            attack_pattern_description = attack.get("description")
            attack_pattern_platforms = attack.get("x_mitre_platforms", [])
            attack_pattern_permissions_required = attack.get(
                "x_mitre_permissions_required", []
            )
            kill_chain_phases = list(
                map(
                    lambda chain: chain.get("phase_name"),
                    attack.get("kill_chain_phases", []),
                )
            )
            attack_pattern_external_id = ""
            external_references = attack.get("external_references")
            for external_reference in external_references:
                if external_reference.get("source_name") == "mitre-attack":
                    attack_pattern_external_id = external_reference.get("external_id")
            attack_pattern = {
                "attack_pattern_name": attack_pattern_name,
                "attack_pattern_stix_id": stix_id,
                "attack_pattern_external_id": attack_pattern_external_id,
                "attack_pattern_description": attack_pattern_description,
                "attack_pattern_platforms": attack_pattern_platforms,
                "attack_pattern_permissions_required": attack_pattern_permissions_required,
                "attack_pattern_kill_chain_phases": kill_chain_phases,
            }
            attack_patterns.append(attack_pattern)
        # print(attack_patterns)
        self.client.attack_pattern.upsert(attack_patterns)

    def _relationships(self, relationships):
        parents = []
        for relationship in relationships:
            source_ref = relationship.get("source_ref")
            target_ref = relationship.get("target_ref")
            parents.append(
                {
                    "parent_attack_pattern": target_ref,
                    "child_attack_pattern": source_ref,
                }
            )
        # TODO
        # self.client.relationships.upsert(parents)

    def _process_message(self) -> None:
        response = self.session.get(url=ENTERPRISE_ATTACK_URI)
        enterprise_attack = response.json()
        objects = enterprise_attack.get("objects")
        tactics = []
        attack_patterns = []
        relationships = []
        # Generate items
        for item in objects:
            object_type = item.get("type")
            if object_type == "attack-pattern":
                attack_patterns.append(item)
            if object_type == "x-mitre-tactic":
                tactics.append(item)
            if (
                object_type == "relationship"
                and item.get("relationship_type") == "subtechnique-of"
            ):
                relationships.append(item)
        # Sync kill chain phases
        self._kill_chain_phases(tactics)
        # Sync attack patterns
        self._attack_patterns(attack_patterns)
        # Sync relationships
        self._relationships(relationships)

    # Start the main loop
    def start(self):
        self.helper.schedule(message_callback=self._process_message, delay=3600)


if __name__ == "__main__":
    openBASMitre = OpenBASMitre()
    openBASMitre.start()
