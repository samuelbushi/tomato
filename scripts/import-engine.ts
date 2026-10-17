import { readFile, realpath, stat } from "node:fs/promises";
import { resolve, sep, join } from "node:path";
import { homedir } from "node:os";
import pg from "pg";
import { PgDatabase } from "../src/database.ts";
import { databaseConfig, secret } from "../src/config.ts";
import { importLegacyEngine } from "../src/engine-import.ts";

let filename: string | undefined, confirmed = false;
for (let index=2; index<process.argv.length; index++) {
  const argument=process.argv[index];
  if (argument==="--export" && filename===undefined) filename=process.argv[++index];
  else if (argument==="--confirm-empty-target" && !confirmed) confirmed=true;
  else throw new Error("invalid_engine_import_arguments");
}
if (!filename || !confirmed) throw new Error("explicit_approved_export_and_empty_target_confirmation_required");
const candidate=resolve(filename), actual=await realpath(candidate);
const privatePilot=join(homedir(),"Library","Application Support","Tomato");
for (const path of [candidate,actual]) {
  if (path.split(sep).some(part=>[".tomato-local",".tomato-dev",".wrangler"].includes(part)) || path===privatePilot || path.startsWith(privatePilot+sep)) throw new Error("protected_engine_input_forbidden");
}
const info=await stat(actual);
if (!info.isFile() || info.size>134217728 || (info.mode&0o077)!==0) throw new Error("engine_export_requires_private_bounded_file");
// Restoring imported cursor high-water marks requires sequence UPDATE authority.
// Keep this offline administrator credential out of the running application.
const database=new PgDatabase(new pg.Pool(await databaseConfig(true)));
try {
  const result=await importLegacyEngine(database,JSON.parse(await readFile(actual,"utf8")),(await secret("DATA_KEY"))!,true);
  console.log(JSON.stringify(result));
} catch (error) {
  const reason=error instanceof Error && /^[a-z_]{1,100}$/.test(error.message) ? error.message : "engine_import_failed";
  const sqlState=error && typeof error==="object" && "code" in error && typeof error.code==="string" && /^[0-9A-Z]{5}$/.test(error.code) ? error.code : null;
  console.error(JSON.stringify({error:"engine_import_failed",reason,sqlState,commitAcknowledged:false}));
  process.exitCode=1;
} finally { await database.close(); }
