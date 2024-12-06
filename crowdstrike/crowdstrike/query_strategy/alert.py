from datetime import datetime

from pydantic import BaseModel, ValidationError
from pyobas.exceptions import OpenBASError
from pyobas.signatures.types import SignatureTypes

from crowdstrike.query_strategy.base import Base


class ProcessDetails(BaseModel):
    filename: str


class DeviceDetails(BaseModel):
    hostname: str


class Item(BaseModel):
    id: str
    filename: str
    parent_details: ProcessDetails
    grandparent_details: ProcessDetails
    device: DeviceDetails

    def get_id(self):
        return self.id

    def get_process_image_names(self):
        return [
            self.filename,
            self.parent_details.filename,
            self.grandparent_details.filename,
        ]

    def get_hostname(self):
        return self.device.hostname


class Alert(Base):
    def get_strategy_name(self):
        return self.__class__

    def get_raw_data(self, start_time: datetime):
        items = []
        for dataframe in self.api.get_alerts_v2(start_time):
            try:
                items.append(Item(**dataframe))
            except ValidationError as ve:
                self.api.helper.collector_logger.warning(
                    f"Skipping alert entry because of unexpected data layout: {ve}"
                )
                continue
        return items

    def extract_signature_data(
        self, data_item: Item, signature_type_str: SignatureTypes
    ):
        if signature_type_str == SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME:
            return data_item.get_process_image_names()
        elif signature_type_str == SignatureTypes.SIG_TYPE_HOSTNAME:
            return data_item.get_hostname()
        else:
            raise OpenBASError(f"Unsupported signature type: {signature_type_str} by strategy {self.get_strategy_name()}")
