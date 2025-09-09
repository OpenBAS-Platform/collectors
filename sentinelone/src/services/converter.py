"""SentinelOne Data Converter.

This module provides conversion functionality for SentinelOne data types.
Handles conversion between different data formats and OAEV data.
"""

import logging
from typing import Any

from .exception import SentinelOneDataConversionError, SentinelOneValidationError
from .model_deep_visibility import DeepVisibilityEvent
from .model_threat import SentinelOneThreat

LOG_PREFIX = "[SentinelOneConverter]"


OBAS_IMPLANT_PREFIX = "obas-implant-"


class Converter:
    """Converter for SentinelOne data to OAEV format."""

    def __init__(self) -> None:
        """Initialize converter with logger.

        Sets up logging for the converter instance.
        """
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"{LOG_PREFIX} SentinelOne data converter initialized")

    def convert_data_to_oaev_data(
        self,
        data: (
            DeepVisibilityEvent
            | SentinelOneThreat
            | list[DeepVisibilityEvent | SentinelOneThreat]
            | None
        ),
    ) -> list[dict[str, Any]]:
        """Convert SentinelOne data to OAEV format.

        Args:
            data: Raw SentinelOne data (can be dv_data or threat_data).

        Returns:
            List of OAEV data dictionaries.

        Raises:
            SentinelOneValidationError: If data format is invalid.
            SentinelOneDataConversionError: If conversion fails.

        """
        if not data:
            self.logger.debug(
                f"{LOG_PREFIX} No data provided for conversion, returning empty list"
            )
            return []

        if not isinstance(data, list):
            data = [data]

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Converting {len(data)} SentinelOne data items to OAEV format"
            )
            oaev_datas = []
            dv_count = 0
            threat_count = 0
            unknown_count = 0

            for i, item in enumerate(data, 1):
                self.logger.debug(f"{LOG_PREFIX} Processing data item {i}/{len(data)}")

                try:
                    if self._is_dv_data(item):
                        oaev_data = self._dv_data(item)
                        dv_count += 1
                        self.logger.debug(
                            f"{LOG_PREFIX} Converted Deep Visibility data item {i}"
                        )
                    elif self._is_threat_data(item):
                        oaev_data = self._threat_data(item)
                        threat_count += 1
                        self.logger.debug(
                            f"{LOG_PREFIX} Converted threat data item {i}"
                        )
                    else:
                        unknown_count += 1
                        self.logger.warning(
                            f"{LOG_PREFIX} Unknown data type for item {i}: {type(item)}"
                        )
                        continue

                    if oaev_data:
                        oaev_datas.append(oaev_data)
                        self.logger.debug(
                            f"{LOG_PREFIX} Successfully converted item {i} to OAEV format"
                        )
                    else:
                        self.logger.debug(
                            f"{LOG_PREFIX} Item {i} conversion resulted in empty OAEV data"
                        )

                except Exception as e:
                    raise SentinelOneDataConversionError(
                        f"Failed to convert data item {i}: {e}"
                    ) from e

            self.logger.info(
                f"{LOG_PREFIX} SentinelOne to OAEV conversion: processed {len(data)} items -> {len(oaev_datas)} results"
            )

            self.logger.info(
                f"{LOG_PREFIX} Conversion completed: {dv_count} DV events, {threat_count} threats, "
                f"{unknown_count} unknown items -> {len(oaev_datas)} OAEV items"
            )
            return oaev_datas

        except SentinelOneDataConversionError:
            raise
        except Exception as e:
            raise SentinelOneDataConversionError(
                f"Unexpected error converting data to OAEV format: {e}"
            ) from e

    def _is_dv_data(self, data: Any) -> bool:
        """Check if data is Deep Visibility data.

        Args:
            data: Data object to check.

        Returns:
            True if data is a DeepVisibilityEvent instance.

        """
        return isinstance(data, DeepVisibilityEvent)

    def _is_threat_data(self, data: Any) -> bool:
        """Check if data is Threat data.

        Args:
            data: Data object to check.

        Returns:
            True if data is a SentinelOneThreat instance.

        """
        return isinstance(data, SentinelOneThreat)

    def _dv_data(
        self, dvdata: DeepVisibilityEvent | SentinelOneThreat
    ) -> dict[str, Any]:
        """Convert Deep Visibility data to OAEV format.

        Args:
            dvdata: Deep Visibility event data.

        Returns:
            OAEV formatted data dictionary.

        Raises:
            SentinelOneValidationError: If input type is invalid.
            SentinelOneDataConversionError: If conversion fails.

        """
        try:
            oaev_data = {}

            if not isinstance(dvdata, DeepVisibilityEvent):
                raise SentinelOneValidationError(
                    f"Invalid input type for DV conversion: {type(dvdata)}"
                )

            if dvdata.src_proc_parent_name and dvdata.src_proc_parent_name.startswith(
                OBAS_IMPLANT_PREFIX
            ):
                oaev_data["parent_process_name"] = {
                    "type": "simple",
                    "data": [dvdata.src_proc_parent_name],
                }
                self.logger.debug(
                    f"{LOG_PREFIX} Using parent process name: {dvdata.src_proc_parent_name}"
                )
            elif dvdata.src_proc_name and dvdata.src_proc_name.startswith(
                OBAS_IMPLANT_PREFIX
            ):
                oaev_data["parent_process_name"] = {
                    "type": "simple",
                    "data": [dvdata.src_proc_name],
                }
                self.logger.debug(
                    f"{LOG_PREFIX} Using process name as parent: {dvdata.src_proc_name}"
                )
            else:
                self.logger.debug(
                    f"{LOG_PREFIX} No OBAS implant process name found in DV data"
                )

            if dvdata.tgt_file_sha1:
                self.logger.debug(
                    f"{LOG_PREFIX} DV data includes target file SHA1: {dvdata.tgt_file_sha1}"
                )

            self.logger.debug(
                f"{LOG_PREFIX} Converted DV data to OAEV with {len(oaev_data)} fields"
            )
            return oaev_data

        except SentinelOneValidationError:
            raise
        except Exception as e:
            raise SentinelOneDataConversionError(
                f"Error converting Deep Visibility data to OAEV: {e}"
            ) from e

    def _threat_data(
        self, threatdata: SentinelOneThreat | DeepVisibilityEvent
    ) -> dict[str, Any]:
        """Convert Threat data to OAEV format.

        Args:
            threatdata: Threat data.

        Returns:
            OAEV formatted data dictionary.

        Raises:
            SentinelOneValidationError: If input type is invalid or threat_id is missing.
            SentinelOneDataConversionError: If conversion fails.

        """
        try:
            if not isinstance(threatdata, SentinelOneThreat):
                raise SentinelOneValidationError(
                    f"Invalid input type for threat conversion: {type(threatdata)}"
                )

            oaev_data = {}

            if threatdata.threat_id:
                oaev_data["threat_id"] = {
                    "type": "simple",
                    "data": [threatdata.threat_id],
                }
                self.logger.debug(
                    f"{LOG_PREFIX} Converted threat with ID: {threatdata.threat_id}"
                )
            else:
                raise SentinelOneValidationError(
                    "Threat data missing threat_id - cannot create proper OAEV data"
                )

            if hasattr(threatdata, "_raw") and threatdata._raw:
                self.logger.debug(
                    f"{LOG_PREFIX} Threat data includes raw API response data"
                )

            self.logger.debug(
                f"{LOG_PREFIX} Converted threat data to OAEV with {len(oaev_data)} fields"
            )
            return oaev_data

        except SentinelOneValidationError:
            raise
        except Exception as e:
            raise SentinelOneDataConversionError(
                f"Error converting threat data to OAEV: {e}"
            ) from e
