import pg from "pg";
import { PgDatabase } from "./database";
import { databaseConfig, secret } from "./config";

const database = new PgDatabase(new pg.Pool(await databaseConfig(true)));
try {
  const password = (await secret("TOMATO_DB_PASSWORD"))!;
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(password)) throw new Error("invalid_database_password");
  // Fixed role identifier, generated alphabet-only literal: no user-controlled SQL.
  await database.query("SELECT pg_advisory_lock(84571021)");
  const role = await database.query("SELECT 1 FROM pg_roles WHERE rolname='tomato_app'");
  if (!role.length) await database.query(`CREATE ROLE tomato_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}'`);
  await database.query("SELECT pg_advisory_unlock(84571021)");
  await database.migrate();
  for (const schema of ["public", "engine", "identity"]) {
    await database.query(`GRANT USAGE ON SCHEMA ${schema} TO tomato_app`);
    await database.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${schema} TO tomato_app`);
    await database.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ${schema} TO tomato_app`);
    await database.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA ${schema} GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tomato_app`);
    await database.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA ${schema} GRANT USAGE, SELECT ON SEQUENCES TO tomato_app`);
  }
  await database.query("REVOKE ALL ON public.tomato_migrations FROM tomato_app");
  console.log("tomato_migrations_complete");
} catch { console.error("tomato_migrations_failed"); process.exitCode = 1; }
finally { await database.close(); }
