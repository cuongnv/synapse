import logging
from typing import Optional

from twisted.internet import defer

from synapse.api.errors import Codes, StoreError, SynapseError
from synapse.types import Requester

from ._base import BaseHandler

logger = logging.getLogger(__name__)


class AddSecurityKeysHandler(BaseHandler):
    """Handler which deals with changing user account passwords"""

    def __init__(self, hs):
        super(AddSecurityKeysHandler, self).__init__(hs)
        self._auth_handler = hs.get_auth_handler()

    @defer.inlineCallbacks
    def add_security_key(
        self,
        user_id: str,
        attestation_object: str,
        client_data_json: str,
        requester: Optional[Requester] = None,
    ):
        
        try:
            yield self.store.register_security_keys(user_id, attestation_object, client_data_json)
        except StoreError as e:
            if e.code == 404:
                raise SynapseError(404, "Unknown user", Codes.NOT_FOUND)
            raise e
