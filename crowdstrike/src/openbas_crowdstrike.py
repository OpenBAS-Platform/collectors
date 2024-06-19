# -*- coding: utf-8 -*-
"""OpenBAS CrowdStrike collector main module."""

from crowdstrike import CrowdStrike

if __name__ == "__main__":
    connector = CrowdStrike()
    connector.run()
