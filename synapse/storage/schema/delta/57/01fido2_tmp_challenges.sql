-- Temporary table store generated challenge when user does register/login via security key. 
-- Associated row will be deleted after finishing register/login routine
CREATE TABLE IF NOT EXISTS fido2_tmp_challenges( 
    user_id TEXT NOT NULL, -- The user_id of user.
    challenge TEXT NOT NULL, -- challenge (random 32 bytes that is encoded with base64)
    type SMALLINT NOT NULL, -- type of challenge (0:REGISTER | 1:LOGIN)
    timestamp BIGINT NOT NULL -- created timestamp
);
