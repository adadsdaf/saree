// Migration runner — uses server's postgres connection
import { readFileSync } from 'fs';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);

// Load env
const dotenv = require('dotenv');
dotenv.config({ override: false });

const url = process.env.DATABASE_URL;
if (!url) { console.error('No DATABASE_URL'); process.exit(1); }

const postgres = (await import('postgres')).default;
const sql = postgres(url, { max: 1 });

// Read all migration files in order
const files = [
  'drizzle/0000_flowery_thundra.sql',
  'drizzle/0001_reflective_fabian_cortez.sql',
  'drizzle/0002_add_advanced_features.sql',
  'drizzle/0003_delivery_fee_tables.sql',
  'drizzle/0004_add_offers_fields.sql',
  'drizzle/0005_add_favorites_table.sql',
  'drizzle/0006_add_missing_tables.sql',
];

let ok = 0, skipped = 0, failed = 0;

for (const file of files) {
  let content;
  try { content = readFileSync(file, 'utf8'); } catch { continue; }
  
  // Split on --> statement-breakpoint or semicolons
  const statements = content
    .split(/-->\s*statement-breakpoint|(?<=;)\s*\n/)
    .map(s => s.replace(/--> statement-breakpoint/g, '').trim())
    .filter(s => s.length > 2 && !s.startsWith('--'));

  console.log(`\n📄 ${file} — ${statements.length} statements`);
  
  for (const stmt of statements) {
    const clean = stmt.endsWith(';') ? stmt : stmt + ';';
    try {
      await sql.unsafe(clean);
      ok++;
    } catch(e) {
      const msg = e.message || '';
      if (msg.includes('already exists') || e.code === '42P07' || e.code === '42701' || e.code === '42710') {
        skipped++;
      } else {
        console.error(`  ❌ ${clean.slice(0,80)}...`);
        console.error(`     ${msg.slice(0,120)}`);
        failed++;
      }
    }
  }
}

// Also run update_schema.sql for extra tables
try {
  const extra = readFileSync('update_schema.sql', 'utf8');
  const stmts = extra.split(';').map(s => s.trim()).filter(s => s.length > 5 && !s.startsWith('--'));
  console.log(`\n📄 update_schema.sql — ${stmts.length} statements`);
  for (const stmt of stmts) {
    try {
      await sql.unsafe(stmt);
      ok++;
    } catch(e) {
      const msg = e.message || '';
      if (msg.includes('already exists') || e.code === '42P07' || e.code === '42701' || e.code === '42710' || msg.includes('does not exist')) {
        skipped++;
      } else {
        failed++;
      }
    }
  }
} catch {}

console.log(`\n✅ Done: ${ok} executed, ${skipped} skipped (already exist), ${failed} failed`);
await sql.end();
