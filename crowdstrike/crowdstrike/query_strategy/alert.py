from datetime import datetime

from crowdstrike.query_strategy.base import Base
from pyobas.signatures.types import SignatureTypes


class Alert(Base):
    class Item:
        def __init__(self, dataframe: dict):
            self._data = dataframe

        def get_id(self):
            return self._data.get("id")

        def get_process_image_names(self):
            return [
                self._data.get("filename"),
                self._data.get("parent_details").get("filename"),
                self._data.get("grandparent_details").get("filename"),
            ]

        def get_hostname(self):
            return self._data.get("device").get("hostname")

    def get_raw_data(self, start_time: datetime):
        return [
            Alert.Item(dataframe) for dataframe in self.api.get_alerts_v2(start_time)
        ]

    def extract_signature_data(self, data_item: Item, signature_type_str):
        if signature_type_str == SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME:
            return data_item.get_process_image_names()
        elif signature_type_str == SignatureTypes.SIG_TYPE_HOSTNAME:
            return data_item.get_hostname()
