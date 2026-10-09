import { AccountSecrets } from "./account-secrets";
import { gunzipSync } from "node:zlib";
import { identifier, integer, record } from "./validation";
import { PgTransaction, type PgDatabase } from "./database";
import type { MonitorRecord, NotificationRecord } from "./types";

const TABLE_COLUMNS: Record<string, readonly string[]> = {
  metadata:["key","value"], wallet:["id","balance","reserved","usage","missed","archive_sequence"],
  deposits:["id","credits"], monitors:["id","next_due","paused","data"],
  jobs:["id","monitor_id","status","expires_at","scheduled_at","data"],
  observations:["id","observed_at","archived","data"], incidents:["id","data"],
  notifications:["id","status","next_due","data"], pulses:["monitor_id","pulse_id","received_at"],
  coverage:["monitor_id","started_at","ended_at","state","evidence_mode"],
  outbox:["id","next_due","message"], retired_monitors:["id","name","deleted_at"],
  grants:["id","reason","created_at"], audit:["id","data"],
  maintenance:["id","monitor_id","starts_at","ends_at","data"], freshness:["monitor_id","observed_at","fresh_until"],
};
const CURSOR_TABLES: Record<string,true> = {observations:true,incidents:true,notifications:true,coverage:true,audit:true};

/** Offline import only: the operator supplies a complete approved SQLite table
 * export and original archive bytes. No live pilot connection or discovery.
 * Each target account must already have its preserved identity and be empty.
 */
export async function importLegacyEngine(database: PgDatabase, input: unknown, dataKey: string, confirmEmptyTarget: boolean): Promise<{accounts:number;rows:number;archives:number}> {
  if (!confirmEmptyTarget) throw new Error("empty_target_confirmation_required");
  const exported = record(input);
  if (exported.version !== 1 || exported.kind !== "tomato-engine-export" || exported.mode !== "hosted" || !Array.isArray(exported.accounts) || !exported.accounts.length || exported.accounts.length > 10000) throw new Error("invalid_engine_export");
  const seen = new Set<string>();
  let rows = 0, archives = 0;
  const accountIds = exported.accounts.map(value => identifier(String(record(value).accountId ?? ""))).sort();
  if (new Set(accountIds).size !== accountIds.length) throw new Error("duplicate_export_account");
  const client = await database.pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL search_path TO engine,public");
    const locked = await client.query("SELECT id FROM engine.accounts WHERE id=ANY($1::text[]) ORDER BY id FOR UPDATE", [accountIds]);
    if (locked.rowCount !== accountIds.length) throw new Error("preserved_identity_accounts_required");
    const tx = new PgTransaction(client);
  for (const value of exported.accounts) {
    const account = record(value), accountId = identifier(String(account.accountId ?? ""));
    if (seen.has(accountId)) throw new Error("duplicate_export_account");
    seen.add(accountId);
    const tables = record(account.tables);
    if (Object.keys(tables).length !== Object.keys(TABLE_COLUMNS).length || Object.keys(tables).some(table => !Object.hasOwn(TABLE_COLUMNS,table))) throw new Error("complete_engine_tables_required");
    if (!Array.isArray(account.archives)) throw new Error("complete_archive_export_required");
    const archiveRecords = account.archives;
    const secrets = new AccountSecrets(dataKey, accountId);
    await tx.query("SELECT set_config('tomato.account_id',$1,true)", [accountId]);
    const counts = await (async () => {
      for (const table of [...Object.keys(TABLE_COLUMNS),"archives"]) {
        if ((await tx.query(`SELECT 1 FROM ${table} LIMIT 1`)).length) throw new Error("engine_import_target_not_empty");
      }
      let importedRows = 0;
      const metadataKeys = new Set<string>();
      for (const [table, columns] of Object.entries(TABLE_COLUMNS)) {
        const values = tables[table];
        if (!Array.isArray(values) || values.length > 1000000) throw new Error("invalid_engine_table_export");
        if (table === "wallet" && values.length !== 1) throw new Error("complete_wallet_required");
        if (table === "monitors" && values.length > 100) throw new Error("account_monitor_limit");
        for (const value of values) {
          const row = { ...record(value) };
          if (Object.keys(row).some(key => !columns.includes(key) && key !== "rowid" && key !== "cursor")) throw new Error("unexpected_export_column");
          if (table === "metadata") {
            metadataKeys.add(String(row.key));
            if (row.key === "account" && row.value !== accountId) throw new Error("export_account_mismatch");
            if (row.key === "engine-mode" && row.value !== "hosted") throw new Error("export_mode_mismatch");
            if (row.key === "notification-defaults") row.value = secrets.encodeDefaults(JSON.parse(String(row.value)));
            if (row.key === "status-page") {
              const page = record(JSON.parse(String(row.value)));
              page.revision = typeof page.revision === "number" ? page.revision : 1;
              row.value = JSON.stringify(page);
            }
          }
          if (table === "monitors") row.data = secrets.encodeMonitor(JSON.parse(String(row.data)) as MonitorRecord);
          if (table === "notifications") {
            const notification = JSON.parse(String(row.data)) as NotificationRecord;
            if (notification.status === "sending") { notification.status="pending"; notification.leaseToken=null; notification.leaseUntil=0; row.status="pending"; }
            row.data = secrets.encodeNotification(notification);
          }
          if (table === "jobs") {
            const job = record(JSON.parse(String(row.data)));
            if (job.status === "running") { job.leaseToken=null; job.leaseUntil=0; }
            row.data=JSON.stringify(job);
          }
          if (table === "coverage" && row.evidence_mode === undefined) row.evidence_mode="legacy";
          const insertionColumns = [...columns];
          const insertionValues = columns.map(column => {
            const value = row[column];
            if (value === undefined || typeof value !== "string" && typeof value !== "number" && value !== null) throw new Error("missing_or_invalid_export_value");
            if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error("unsafe_export_integer");
            return value;
          });
          if (CURSOR_TABLES[table]) {
            insertionColumns.push("cursor");
            insertionValues.push(integer(row.cursor ?? row.rowid,1,Number.MAX_SAFE_INTEGER,"export_cursor"));
          }
          await tx.query(`INSERT INTO ${table}(${insertionColumns.join(",")})${CURSOR_TABLES[table]?" OVERRIDING SYSTEM VALUE":""} VALUES(${insertionColumns.map((_,index)=>`$${index+1}`).join(",")})`, insertionValues);
          importedRows++;
        }
        if (CURSOR_TABLES[table]) await tx.query(`SELECT setval('engine.${table}_cursor_seq',GREATEST((SELECT last_value FROM engine.${table}_cursor_seq),COALESCE((SELECT MAX(cursor) FROM ${table}),1)),true)`);
      }
      if (!metadataKeys.has("heartbeat-usage")) throw new Error("provable_cumulative_heartbeat_usage_required");
      await tx.query("INSERT INTO metadata(key,value) VALUES('engine-mode','hosted') ON CONFLICT DO NOTHING");
      const page = await tx.query<{value:string}>("SELECT value FROM metadata WHERE key='status-page'");
      if (page[0] && !metadataKeys.has("status-page-revision")) await tx.query("INSERT INTO metadata(key,value) VALUES('status-page-revision',$1)",[String(record(JSON.parse(page[0].value)).revision)]);
      for (const value of archiveRecords) {
        const archive=record(value);
        if (typeof archive.id!=="string" || !/^\d{12,20}$/.test(archive.id) || typeof archive.payloadBase64!=="string" || archive.payloadBase64.length>2796204 || !/^[A-Za-z0-9+/]*={0,2}$/.test(archive.payloadBase64)) throw new Error("invalid_archive_export");
        const bytes=Buffer.from(archive.payloadBase64,"base64");
        if (bytes.length>2097152) throw new Error("archive_batch_limit");
        const archivePayload=record(JSON.parse(gunzipSync(bytes,{maxOutputLength:4194304}).toString("utf8")));
        if (archivePayload.version!==1 || archivePayload.accountId!==accountId || !Array.isArray(archivePayload.observations) || archivePayload.observations.length>100) throw new Error("archive_account_or_format_mismatch");
        await tx.query("INSERT INTO archives(id,payload,created_at) VALUES($1,$2,$3)",[archive.id,bytes,integer(archive.createdAt,0,Number.MAX_SAFE_INTEGER,"archive_created_at")]);
      }
      return {rows:importedRows,archives:archiveRecords.length};
    })();
    rows += counts.rows; archives += counts.archives;
  }
    await client.query("COMMIT");
    return {accounts:seen.size,rows,archives};
  } catch (error) { await client.query("ROLLBACK"); throw error; }
  finally { client.release(); }
}
