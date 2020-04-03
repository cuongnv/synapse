import logging

from twisted.internet import defer
from twisted.internet.defer import Deferred

from synapse.api.errors import Codes, StoreError
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import Database
from synapse.types import UserID

logger = logging.getLogger(__name__)


class FIDO2ChallengesWorkerStore(SQLBaseStore):
    def __init__(self, database: Database, db_conn, hs):
        super(FIDO2ChallengesWorkerStore, self).__init__(database, db_conn, hs)
        self.config = hs.config
        self.clock = hs.get_clock()
    
    def get_latest_challenge_by_user(self, user_id, type):
        return self.db.simple_select_list_paginate(
            table="fido2_tmp_challenges",
            orderby = "timestamp",
            start = 0,
            limit= 1,
            retcols=["challenge"],
            keyvalues={"user_id": user_id, "type":type},
            order_direction="DESC",
            desc="get_latest_challenge_by_user",
        )

class FIDO2ChallengesStore(FIDO2ChallengesWorkerStore):
    def __init__(self, database: Database, db_conn, hs):
        super(FIDO2ChallengesStore, self).__init__(database, db_conn, hs)

    def add_challenge_to_user(
        self,
        user_id,
        challenge, 
        type
    ):
        return self.db.runInteraction(
            "add_challenge_to_user",
            self._add_challenge_to_user,
            user_id,
            challenge,
            type
        )

    def _add_challenge_to_user(
        self,
        txn,
        user_id,
        challenge,
        type
    ):
        user_id_obj = UserID.from_string(user_id)
        now = int(self.clock.time())
        try:
            self.db.simple_insert_txn(
                txn,
                "fido2_tmp_challenges",
                values={
                    "user_id": user_id,
                    "challenge": challenge,
                    "type":type,
                    "timestamp": now
                },
            )

        except self.database_engine.module.IntegrityError:
            raise StoreError(400, "Another FIDO2 flow in-progress.", errcode=Codes.FIDO2_FLOW_IN_PROCESS)

    def delete_challeges_of_user(self, user_id, type):
        try:
            self.db.simple_delete("fido2_tmp_challenges", {"user_id": user_id, "type":type}, "delete_challeges_of_user")
        except:
            #TODO: Just ignore it. We should create background job to delete all old challenges
            logger.info("Can not delete FIDO2 challenges.")
            #raise StoreError(400, "Can not delete FIDO2 challenges.", errcode=Codes.FIDO2_DELETE_CHALLENGE)