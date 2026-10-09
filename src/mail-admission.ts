import type { PgDatabase } from "./database";
import { ApiError } from "./validation";

export interface MailBudget { daily: number; hourly: number }
export function validateMailBudget(budget: MailBudget): void {
  if (!Number.isSafeInteger(budget.daily) || !Number.isSafeInteger(budget.hourly) || budget.daily < 1 || budget.daily > 100000 || budget.hourly < 1 || budget.hourly > budget.daily) throw new Error("invalid_smtp_mail_budget");
}
/** Global health preflight is read-only and runs before auth's account-existence lookup. */
export async function checkMailBudget(database: PgDatabase, budget?: MailBudget): Promise<void> {
  if (!budget) return;
  const now = Date.now(), day = Math.floor(now / 86400000) * 86400000, hour = Math.floor(now / 3600000) * 3600000;
  const rows = (await database.mailAdmissionPool.query<{ period: string; attempts: number }>("SELECT period,attempts FROM identity.mail_admission WHERE (period='day' AND window_started=$1) OR (period='hour' AND window_started=$2)", [day, hour])).rows;
  if (rows.some(row => row.attempts >= (row.period === "day" ? budget.daily : budget.hourly))) throw new ApiError(503, "smtp_budget_exhausted");
}
/** Reserve before actual SMTP I/O. Failures consume the slot: delivery may be ambiguous. */
export async function admitMail(database: PgDatabase, budget?: MailBudget): Promise<void> {
  if (!budget) return;
  const now = Date.now(), day = Math.floor(now / 86400000) * 86400000, hour = Math.floor(now / 3600000) * 3600000, client = await database.mailAdmissionPool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended('tomato.mail.admission',0))");
    const rows = (await client.query<{ period: string; attempts: number }>("SELECT period,attempts FROM identity.mail_admission WHERE (period='day' AND window_started=$1) OR (period='hour' AND window_started=$2)", [day, hour])).rows;
    if (rows.some(row => row.attempts >= (row.period === "day" ? budget.daily : budget.hourly))) throw new ApiError(503, "smtp_budget_exhausted");
    await client.query("DELETE FROM identity.mail_admission WHERE window_started<$1", [day - 86400000]);
    await client.query("INSERT INTO identity.mail_admission(period,window_started,attempts) VALUES('day',$1,1),('hour',$2,1) ON CONFLICT(period,window_started) DO UPDATE SET attempts=identity.mail_admission.attempts+1", [day, hour]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
}
