CREATE TABLE IF NOT EXISTS security_keys(
    user_id TEXT NOT NULL, -- The user_id of user.
    credential_id TEXT NOT NULL, -- credential_id of registed security key
    credential_public_key TEXT NOT NULL, -- credential public key of registed security key
    attestation_object_json TEXT NOT NULL, -- The attestationObject is responsed from registed security key .
    client_data_json TEXT NOT NULL, -- The clientDataJson is responsed from registed security key .
    CONSTRAINT security_keys_uniqueness UNIQUE (credential_id)
);
