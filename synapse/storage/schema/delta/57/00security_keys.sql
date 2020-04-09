CREATE TABLE IF NOT EXISTS security_keys(
    user_id TEXT NOT NULL, -- The user_id of user.
    rp_id TEXT NOT NULL, -- rp_id
    credential_id TEXT NOT NULL, -- credential_id of registed security key
    credential_public_key TEXT NOT NULL, -- credential public key of registed security key
    `certificate` TEXT NOT NULL, -- certificate of registed security key
    certificate_issuer TEXT NOT NULL, -- certificate_issuer of registed security key
    certificate_subject TEXT NOT NULL, -- certificate_subject of registed security key
    AAGUID TEXT NOT NULL, -- AAGUID of registed security key
    attestation_object_json TEXT NOT NULL, -- The attestationObject is responsed from registed security key .
    client_data_json TEXT NOT NULL, -- The clientDataJson is responsed from registed security key .
    CONSTRAINT security_keys_uniqueness UNIQUE (credential_id)
);
