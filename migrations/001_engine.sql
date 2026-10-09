CREATE SCHEMA IF NOT EXISTS engine;
CREATE TABLE engine.accounts (
  id text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{1,64}$'),
  name text NOT NULL DEFAULT 'Workspace',
  created_at bigint NOT NULL DEFAULT (extract(epoch FROM clock_timestamp())*1000)::bigint
);
CREATE TABLE engine.metadata(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),key text NOT NULL,value text NOT NULL,PRIMARY KEY(account_id,key));
CREATE TABLE engine.wallet(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),id integer NOT NULL CHECK(id=1),balance bigint NOT NULL CHECK(balance BETWEEN 0 AND 9007199254740991),reserved bigint NOT NULL CHECK(reserved>=0 AND reserved<=balance),usage bigint NOT NULL CHECK(usage>=0),missed bigint NOT NULL CHECK(missed>=0),archive_sequence bigint NOT NULL CHECK(archive_sequence>=0),PRIMARY KEY(account_id,id));
CREATE TABLE engine.deposits(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),id text NOT NULL,credits bigint NOT NULL CHECK(credits>0),PRIMARY KEY(account_id,id));
CREATE TABLE engine.monitors(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),id text NOT NULL,next_due bigint NOT NULL,paused integer NOT NULL CHECK(paused IN (0,1)),data text NOT NULL CHECK(jsonb_typeof(data::jsonb)='object'),PRIMARY KEY(account_id,id));
CREATE INDEX monitors_due ON engine.monitors(account_id,next_due) WHERE paused=0;
CREATE TABLE engine.jobs(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),id text NOT NULL,monitor_id text NOT NULL,status text NOT NULL CHECK(status IN ('pending','running','done','missed','cancelled')),expires_at bigint NOT NULL,scheduled_at bigint NOT NULL,data text NOT NULL CHECK(jsonb_typeof(data::jsonb)='object'),PRIMARY KEY(account_id,id));
CREATE INDEX jobs_expiry ON engine.jobs(account_id,status,expires_at);
CREATE INDEX jobs_monitor ON engine.jobs(account_id,monitor_id,status);
CREATE UNIQUE INDEX jobs_slot_fence ON engine.jobs(account_id,monitor_id,((data::jsonb->>'revision')::bigint),scheduled_at) WHERE data::jsonb->>'role'='primary' AND (data::jsonb->>'manual') IS DISTINCT FROM 'true';
CREATE UNIQUE INDEX jobs_manual_inflight ON engine.jobs(account_id,monitor_id) WHERE status IN ('pending','running') AND data::jsonb->>'manual'='true';
CREATE UNIQUE INDEX jobs_confirmation_fence ON engine.jobs(account_id,(data::jsonb->>'rootJobId')) WHERE data::jsonb->>'role'='confirmation';
CREATE TABLE engine.observations(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),id text NOT NULL,cursor bigint GENERATED ALWAYS AS IDENTITY,observed_at bigint NOT NULL,archived integer NOT NULL DEFAULT 0 CHECK(archived IN (0,1)),data text NOT NULL CHECK(jsonb_typeof(data::jsonb)='object'),PRIMARY KEY(account_id,id));
CREATE INDEX observations_account_cursor ON engine.observations(account_id,cursor DESC);
CREATE INDEX observations_retention ON engine.observations(account_id,archived,observed_at);
CREATE TABLE engine.incidents(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),id text NOT NULL,cursor bigint GENERATED ALWAYS AS IDENTITY,data text NOT NULL CHECK(jsonb_typeof(data::jsonb)='object'),PRIMARY KEY(account_id,id));
CREATE INDEX incidents_account_cursor ON engine.incidents(account_id,cursor DESC);
CREATE TABLE engine.notifications(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),id text NOT NULL,cursor bigint GENERATED ALWAYS AS IDENTITY,status text NOT NULL CHECK(status IN ('pending','sending','delivered','failed')),next_due bigint NOT NULL,data text NOT NULL CHECK(jsonb_typeof(data::jsonb)='object'),PRIMARY KEY(account_id,id));
CREATE INDEX notifications_account_cursor ON engine.notifications(account_id,cursor DESC);
CREATE TABLE engine.pulses(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),monitor_id text NOT NULL,pulse_id text NOT NULL,received_at bigint NOT NULL,PRIMARY KEY(account_id,monitor_id,pulse_id));
CREATE TABLE engine.coverage(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),monitor_id text NOT NULL,cursor bigint GENERATED ALWAYS AS IDENTITY,started_at bigint NOT NULL,ended_at bigint,state text NOT NULL CHECK(state IN ('UP','DOWN','UNKNOWN','SUSPECT','RECOVERING','PAUSED','MAINTENANCE')),evidence_mode text NOT NULL DEFAULT 'legacy' CHECK(evidence_mode IN ('legacy','freshness','heartbeat-deadline')),PRIMARY KEY(account_id,monitor_id,started_at),CHECK(ended_at IS NULL OR ended_at>started_at));
CREATE UNIQUE INDEX coverage_one_open ON engine.coverage(account_id,monitor_id) WHERE ended_at IS NULL;
CREATE INDEX coverage_account_cursor ON engine.coverage(account_id,cursor DESC);
CREATE TABLE engine.outbox(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),id text NOT NULL,next_due bigint NOT NULL,message text NOT NULL CHECK(jsonb_typeof(message::jsonb)='object'),dispatch_token text,dispatch_until bigint NOT NULL DEFAULT 0,PRIMARY KEY(account_id,id));
CREATE INDEX outbox_due ON engine.outbox(account_id,next_due,dispatch_until);
CREATE TABLE engine.retired_monitors(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),id text NOT NULL,name text NOT NULL,deleted_at bigint NOT NULL,PRIMARY KEY(account_id,id));
CREATE TABLE engine.grants(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),id text NOT NULL,reason text NOT NULL,created_at bigint NOT NULL,PRIMARY KEY(account_id,id));
CREATE TABLE engine.audit(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),id text NOT NULL,cursor bigint GENERATED ALWAYS AS IDENTITY,data text NOT NULL CHECK(jsonb_typeof(data::jsonb)='object'),PRIMARY KEY(account_id,id));
CREATE INDEX audit_account_cursor ON engine.audit(account_id,cursor DESC);
CREATE TABLE engine.maintenance(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),id text NOT NULL,monitor_id text NOT NULL,starts_at bigint NOT NULL,ends_at bigint NOT NULL,data text NOT NULL CHECK(jsonb_typeof(data::jsonb)='object'),PRIMARY KEY(account_id,id),CHECK(ends_at>starts_at));
CREATE TABLE engine.freshness(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),monitor_id text NOT NULL,observed_at bigint NOT NULL,fresh_until bigint NOT NULL,PRIMARY KEY(account_id,monitor_id,observed_at),CHECK(fresh_until>=observed_at));
CREATE INDEX freshness_expiry ON engine.freshness(account_id,fresh_until);
CREATE TABLE engine.archives(account_id text NOT NULL DEFAULT current_setting('tomato.account_id') REFERENCES engine.accounts(id),id text NOT NULL,payload bytea NOT NULL CHECK(octet_length(payload)<=2097152),created_at bigint NOT NULL,PRIMARY KEY(account_id,id));
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['metadata','wallet','deposits','monitors','jobs','observations','incidents','notifications','pulses','coverage','outbox','retired_monitors','grants','audit','maintenance','freshness','archives'] LOOP
    EXECUTE format('ALTER TABLE engine.%I ENABLE ROW LEVEL SECURITY',t);
    EXECUTE format('ALTER TABLE engine.%I FORCE ROW LEVEL SECURITY',t);
    EXECUTE format('CREATE POLICY account_isolation ON engine.%I USING (account_id = current_setting(''tomato.account_id'',true)) WITH CHECK (account_id = current_setting(''tomato.account_id'',true))',t);
  END LOOP;
END $$;
