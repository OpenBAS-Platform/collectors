######################
# CROWDSTRIKE UTILS #
######################


class Utils:
    @staticmethod
    def format_ioc(ioc_type, ioc):
        return {
            "type": ioc_type,
            "value": ioc["value"],
            "description": ioc.get("description", ""),
        }
