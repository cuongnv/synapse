# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017-2018 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import re, base64

from twisted.internet import defer
from twisted.internet.defer import Deferred

from synapse.api.errors import Codes, StoreError
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import Database
from synapse.types import UserID
import json

logger = logging.getLogger(__name__)


class SecurityKeysWorkerStore(SQLBaseStore):
    def __init__(self, database: Database, db_conn, hs):
        super(SecurityKeysWorkerStore, self).__init__(database, db_conn, hs)

        self.config = hs.config
        self.clock = hs.get_clock()

    def get_certificate_by_credential_id(self, credential_id):
        return self.db.simple_select_one(
            table="security_keys",
            keyvalues={"credential_id": credential_id},
            retcols=[
                "certificate"
            ],
            allow_none=True,
            desc="get_certificate_by_credential_id",
        )

    def get_credential_lists_by_id(self, user_id):
        return self.db.simple_select_list(
            table="security_keys",
            keyvalues={"user_id": user_id},
            retcols=[
                "credential_id",
                "credential_public_key",
                "key_name"
            ],
            desc="get_credential_lists_by_id",
        )

    def get_user_by_credential_id(self, credential_id):
        """Get a user from the given credential id.

        Args:
            token (str): The credential id of a user.
        Returns:
            defer.Deferred: None, if the credential id did not match, otherwise dict
                including the keys `user_id`, `credential_public_key`.
        """
        return self.db.runInteraction(
            "get_user_by_credential_id", self._query_for_auth, credential_id
        )

    def _query_for_auth(self, txn, credential_id):
        sql = (
            "SELECT security_keys.user_id, security_keys.credential_public_key"
            " FROM security_keys"
            " WHERE credential_id = ?"
        )

        txn.execute(sql, (credential_id,))
        rows = self.db.cursor_to_dict(txn)
        if rows:
            return rows[0]

        return None

class SecurityKeysStore(SecurityKeysWorkerStore):
    def __init__(self, database: Database, db_conn, hs):
        super(SecurityKeysStore, self).__init__(database, db_conn, hs)

    @defer.inlineCallbacks
    def add_security_key_to_user(self, user_id, key_name, attestation_obj, client_data_json):
        """Adds an security key for the given user.

        Args:
            user_id (str): The user ID.
            attestation_object (json object): The attestation object that returned from security key.
            client_data_json (str): The client data json object that returned from platform
        Raises:
            StoreError if there was a problem adding this.
        """
        credential_id = attestation_obj["credential_id"]
        credential_public_key = attestation_obj["credential_public_key"]
        yield self.db.simple_insert(
            "security_keys",
            {
                "user_id": user_id,
                "key_name":key_name,
                "rp_id":attestation_obj['rp_id'],
                "credential_id": credential_id,
                "credential_public_key": credential_public_key,
                "certificate":attestation_obj['certificate'],
                "certificate_issuer": attestation_obj['certificate_issuer'],
                "certificate_subject":attestation_obj['certificate_subject'],
                "AAGUID":base64.b64encode(attestation_obj["AAGUID"]),
                "attestation_object_json": json.dumps(attestation_obj),
                "client_data_json": client_data_json,
            },
            desc="add_security_key_to_user",
        )

    def register_security_keys(
        self,
        user_id,
        key_name,
        attestation_object_json, 
        client_data_json
    ):
        """Attempts to register an account.

        Args:
            user_id (str): The desired user ID to register.
            attestation_object_json (str): The attestation object that returned from security key.
            client_data_json (str): The client data json object that returned from platform

        Raises:
            StoreError if the user_id could not be registered.
        """
        return self.db.runInteraction(
            "register_security_key_to_user",
            self._register_security_key_to_user,
            user_id,
            key_name,
            attestation_object_json,
            client_data_json
        )

    def _register_security_key_to_user(
        self,
        txn,
        user_id,
        key_name,
        attestation_obj,
        client_data_json
    ):
        user_id_obj = UserID.from_string(user_id)

        now = int(self.clock.time())

        try:
            credential_id = attestation_obj["credential_id"]
            credential_public_key = attestation_obj["credential_public_key"]
            self.db.simple_insert_txn(
                txn,
                "security_keys",
                values={
                    "user_id": user_id,
                    "key_name":key_name,
                    "rp_id":attestation_obj['rp_id'],
                    "credential_id": base64.b64encode(credential_id).decode('ascii'),
                    "credential_public_key": credential_public_key,
                    "certificate":attestation_obj['certificate'].decode('ascii'),
                    "certificate_issuer": attestation_obj['certificate_issuer'],
                    "certificate_subject":attestation_obj['certificate_subject'],
                    "AAGUID":base64.b64encode(attestation_obj["AAGUID"]).decode('ascii'),
                    "attestation_object_json": '',
                    "client_data_json": client_data_json,
                },
            )

        except self.database_engine.module.IntegrityError:
            raise StoreError(400, "Credential ID already registed.", errcode=Codes.FIDO2_SECURITY_KEY_IN_USE)

    def delete_security_key_by_credential_id(self, user_id, credential_id):
        return self.db.runInteraction(
            "register_security_key_to_user",
            self._delete_security_key_by_credential_id,
            user_id,
            credential_id
        )
    
    def _delete_security_key_by_credential_id(
        self,
        txn,
        user_id,
        credential_id
    ):
        self.db.simple_delete_txn(
            txn,"security_keys",keyvalues={"user_id":user_id,"credential_id": credential_id}
        )