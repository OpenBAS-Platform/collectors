from unittest.mock import Mock, patch

from helpers import OpenBASCollectorHelper, OpenBASConfigHelper, OpenBASDetectionHelper
from pyobas.signatures.signature_type import SignatureType
from pyobas.signatures.types import MatchTypes, SignatureTypes

from crowdstrike.crowdstrike.crowdstrike_api_handler import CrowdstrikeApiHandler

DEFAULT_COLLECTOR_CONFIG = {
    "openbas_url": {"data": "http://fake_openbas_base_url"},
    "openbas_token": {"data": "openbas_uuid_token"},
    # Config information
    "collector_id": {"data": "collector_uuid_identifier"},
    "collector_name": {"data": "CrowdStrike Endpoint Security"},
    "collector_type": {"data": "openbas_crowdstream"},
    "collector_period": {"data": 60},
    "collector_log_level": {"data": "info"},
    "collector_platform": {"data": "windows"},
    # CrowdStrike
    "crowdstrike_client_id": {"data": "some_client_id"},
    "crowdstrike_client_secret": {"data": "very_secret_token"},
    "crowdstrike_api_base_url": {"data": "http://fake_crowdstrike_api_base_url"},
}

DEFAULT_SIGNATURE_TYPES = [
    SignatureType(
        SignatureTypes.SIG_TYPE_HOSTNAME, match_type=MatchTypes.MATCH_TYPE_SIMPLE
    ),
    SignatureType(
        SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
        match_type=MatchTypes.MATCH_TYPE_FUZZY,
        match_score=95,
    ),
]

FAKE_DOCUMENT = {"document_id": "fake_document_id"}

FAKE_SECURITY_PLATFORM = {"asset_id": "fake_asset_id"}

default_fixtures = {}


def get_default_openbas_config_helper(
    config: dict = DEFAULT_COLLECTOR_CONFIG,
) -> OpenBASConfigHelper:
    return OpenBASConfigHelper(variables=config, base_path="fake_path")


@patch("pyobas.apis.document.DocumentManager.upsert")
@patch("pyobas.apis.security_platform.SecurityPlatformManager.upsert")
@patch("pyobas.mixins.CreateMixin.create")
@patch("builtins.open")
def get_default_openbas_collector_helper(
    mockOpen,
    mockMixinCreate,
    mockSecurityPlatformUpsert,
    mockDocumentUpsert,
    config: OpenBASConfigHelper = get_default_openbas_config_helper(),
) -> OpenBASCollectorHelper:
    mockDocumentUpsert.return_value = FAKE_DOCUMENT
    mockSecurityPlatformUpsert.return_value = FAKE_SECURITY_PLATFORM
    mockOpen.return_value = None
    return OpenBASCollectorHelper(
        config=config,
        icon="some.png",
        security_platform_type=config.get_conf("collector_platform"),
        connect_run_and_terminate=True,
    )


def get_default_signature_types(
    signature_types: [SignatureTypes] = DEFAULT_SIGNATURE_TYPES,
) -> [SignatureType]:
    return signature_types


def get_default_detection_helper(
    helper: OpenBASCollectorHelper = get_default_openbas_collector_helper(),
    signature_types: [SignatureType] = get_default_signature_types(),
):
    return OpenBASDetectionHelper(
        logger=helper.collector_logger,
        relevant_signatures_types=[
            signature_type.label for signature_type in signature_types
        ],
    )


def get_default_api_handler(
    helper: OpenBASCollectorHelper = get_default_openbas_collector_helper(),
) -> CrowdstrikeApiHandler:
    return CrowdstrikeApiHandler(
        helper=helper,
        client_id=helper.config_helper.get_conf("crowdstrike_client_id"),
        client_secret=helper.config_helper.get_conf("crowdstrike_client_secret"),
        base_url=helper.config_helper.get_conf("crowdstrike_api_base_url"),
    )
