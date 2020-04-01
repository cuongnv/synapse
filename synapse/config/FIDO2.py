from synapse.python_dependencies import DependencyException, check_requirements

from ._base import Config, ConfigError


class FIDO2Config(Config):
    section = "FIDO2"

    def read_config(self, config, **kwargs):
        FIDO2_config = config.get("FIDO2")
        if FIDO2_config is None:
            FIDO2_config = {}

        self.FIDO2_enabled = FIDO2_config.get("enabled", False)
        if not self.FIDO2_enabled:
            return

        self.timeout = FIDO2_config.get("timeout",60000)
        self.attestation = FIDO2_config.get("attestation","none")
        self.authenticatorAttachment = FIDO2_config.get("authenticatorAttachment","cross-platform")
        self.requireResidentKey = FIDO2_config.get("requireResidentKey",False)
        self.userVerification = FIDO2_config.get("userVerification","preferred")

    def generate_config_section(cls, **kwargs):
        return """\
        ## FIDO2 ##

        # https://fidoalliance.org/fido2/
        #
        FIDO2:
            enabled: false
            timeout: 60000
            attestation: "none" #direct, indirect, none
            authenticatorAttachment: "cross-platform"
            requireResidentKey: false
            userVerification: "preferred" #preferred, required, or discouraged
        """
