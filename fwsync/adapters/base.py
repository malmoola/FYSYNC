"""Adapter interface. Done: lina, fmc (FMC REST snapshot). Planned: panos (Palo Alto XML), fortigate (FortiOS conf)."""


class Adapter:
    vendor = 'base'

    @staticmethod
    def detect(text):
        return False

    def parse(self, text, name):
        raise NotImplementedError
