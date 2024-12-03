from abc import ABC, abstractmethod


class Base(ABC):
    def __init__(self, api_handler):
        self.api = api_handler

    @abstractmethod
    def get_raw_data(self, start_time):
        pass

    @abstractmethod
    def extract_signature_data(self, data_item, signature_type):
        pass

    def get_signature_data(self, data_item, signature_types):
        return {
            signature_type.label: signature_type.make_struct_for_matching(
                self.extract_signature_data(data_item, signature_type.label)
            )
            for signature_type in signature_types
        }
