CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    state TEXT NOT NULL,
    callback_config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE workloads (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    identity_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE tool_registry (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    tool TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    runtime_class TEXT NOT NULL,
    config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE connectors (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    kind TEXT NOT NULL,
    config_ciphertext BYTEA NOT NULL,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE delegations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    claims_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    workload_id TEXT NOT NULL REFERENCES workloads(id),
    delegation_id TEXT REFERENCES delegations(id),
    agent_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    tool_context_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    workload_hash TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE capability_policies (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    capability TEXT NOT NULL,
    resource_kind TEXT NOT NULL,
    allowed_delivery_modes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    default_ttl_seconds INTEGER NOT NULL,
    max_ttl_seconds INTEGER NOT NULL,
    approval_mode TEXT NOT NULL,
    required_tool_tags_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    cel_condition TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    grant_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    approved_by TEXT,
    reason TEXT NOT NULL,
    comment TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE grants (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    session_id TEXT NOT NULL REFERENCES sessions(id),
    tool TEXT NOT NULL,
    capability TEXT NOT NULL,
    resource_ref TEXT NOT NULL,
    delivery_mode TEXT NOT NULL,
    connector_kind TEXT NOT NULL,
    approval_id TEXT REFERENCES approvals(id),
    artifact_ref TEXT,
    state TEXT NOT NULL,
    requested_ttl_seconds INTEGER NOT NULL,
    effective_ttl_seconds INTEGER NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE approvals
    ADD CONSTRAINT approvals_grant_id_fkey
    FOREIGN KEY (grant_id) REFERENCES grants(id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE artifacts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    session_id TEXT NOT NULL REFERENCES sessions(id),
    grant_id TEXT NOT NULL REFERENCES grants(id),
    handle TEXT,
    kind TEXT NOT NULL,
    connector_kind TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    recipient_binding_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    single_use BOOLEAN NOT NULL DEFAULT TRUE,
    state TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at TIMESTAMPTZ
);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    event_type TEXT NOT NULL,
    session_id TEXT,
    run_id TEXT,
    grant_id TEXT,
    actor TEXT NOT NULL,
    tool TEXT,
    capability TEXT,
    resource_ref TEXT,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash BYTEA,
    event_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_tenant_run_id
    ON sessions (tenant_id, run_id);

CREATE INDEX idx_grants_tenant_session_state
    ON grants (tenant_id, session_id, state);

CREATE INDEX idx_approvals_tenant_state_expires
    ON approvals (tenant_id, state, expires_at);

CREATE INDEX idx_audit_events_tenant_run_created
    ON audit_events (tenant_id, run_id, created_at);

CREATE INDEX idx_artifacts_tenant_expires_state
    ON artifacts (tenant_id, expires_at, state);

CREATE UNIQUE INDEX idx_artifacts_handle
    ON artifacts (handle)
    WHERE handle IS NOT NULL;
