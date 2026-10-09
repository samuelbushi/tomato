import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { types, type Pool, type PoolClient, type QueryResultRow } from "pg";
import { ApiError, identifier } from "./validation";

types.setTypeParser(20, value => {
  const number = Number(value);
  if (!Number.isSafeInteger(number)) throw new Error("database_integer_out_of_range");
  return number;
});

export class PgTransaction {
  constructor(private readonly client: PoolClient) {}
  async query<T = QueryResultRow>(sql: string, values: unknown[] = []): Promise<T[]> {
    return (await this.client.query(sql, values)).rows as T[];
  }
}

/** Account operations are serialized by a persistent row lock, across processes.
 * No callback performs probe, SMTP, webhook or archive compression I/O.
 */
export class PgDatabase {
  constructor(readonly pool: Pool) {
    // pg evicts a failed idle connection; active query/transaction errors still reject.
    // Its required error event must never crash Node or print the attached Client.
    pool.on("error", error => {
      const code = "code" in error && typeof error.code === "string" && /^[0-9A-Z]{5}$/.test(error.code) ? error.code : "unknown";
      console.error(`tomato_database_idle_connection_error:${code}`);
    });
  }
  async query<T = QueryResultRow>(sql: string, values: unknown[] = []): Promise<T[]> {
    return (await this.pool.query(sql, values)).rows as T[];
  }
  async transaction<T>(accountId: string, callback: (tx: PgTransaction) => Promise<T>): Promise<T> {
    identifier(accountId);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL search_path TO engine, public");
      await client.query("SELECT set_config('tomato.account_id',$1,true)", [accountId]);
      const account = await client.query("SELECT id FROM engine.accounts WHERE id=$1 FOR UPDATE", [accountId]);
      if (!account.rowCount) throw new ApiError(404, "account_not_found");
      const result = await callback(new PgTransaction(client));
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }
  async migrate(directory = "migrations"): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("SELECT pg_advisory_lock(746662091)");
      await client.query("CREATE TABLE IF NOT EXISTS public.tomato_migrations(version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())");
      const files = (await readdir(directory)).filter(file => /^\d+[a-zA-Z0-9_-]*\.sql$/.test(file)).sort();
      for (const file of files) {
        const sql = await readFile(resolve(directory, file), "utf8");
        const checksum = createHash("sha256").update(sql).digest("hex");
        const previous = await client.query<{ checksum: string }>("SELECT checksum FROM public.tomato_migrations WHERE version=$1", [file]);
        if (previous.rows[0]) {
          if (previous.rows[0].checksum !== checksum) throw new Error("applied_migration_changed");
          continue;
        }
        await client.query("BEGIN");
        try {
          await client.query(sql);
          await client.query("INSERT INTO public.tomato_migrations(version,checksum) VALUES($1,$2)", [file, checksum]);
          await client.query("COMMIT");
        } catch (error) { await client.query("ROLLBACK"); throw error; }
      }
    } finally {
      await client.query("SELECT pg_advisory_unlock(746662091)");
      client.release();
    }
  }
  async close(): Promise<void> { await this.pool.end(); }
}
