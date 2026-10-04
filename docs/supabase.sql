-- PushWarden central event table for Supabase (Postgres 15 or newer).
--
-- Run this once in the Supabase SQL editor. It is safe to run again.
--
-- Machines get the project's public key (called "anon" or "publishable"),
-- and this script lets that key INSERT only: it cannot read, change or
-- delete a row, so it is safe to place in every install's config. You read
-- the data in the dashboard or the SQL editor, which act as the owner.
-- Never put the "service_role" or "secret" key on a machine.

create table if not exists public.pushwarden_events (
    id          bigint generated always as identity primary key,
    received_at timestamptz not null default now(),
    event_id    text not null unique,          -- makes a repeated upload harmless
    machine_id  text not null,                 -- random per install, not a host name
    ts          timestamptz not null,
    ver         text,
    iocs        text,
    os          text,
    ctx         text,                          -- guard, guard-full, guard-quick, realtime, scan, github-clean, cli, update
    kind        text not null,                 -- finding, action, decision, sweep, guard, update, error, feedback
    sev         text,
    category    text,
    threat      text,
    title       text,
    path        text,                          -- home folder shown as ~
    cmd         text,                          -- secrets masked
    matched     text,                          -- the exact text that triggered the finding
    why         text,
    response    text,
    action      text,
    ok          boolean,
    evidence    jsonb,
    sweep       text,
    finding_key text,
    note        text,
    data        jsonb
);

create index if not exists pushwarden_events_ts      on public.pushwarden_events (ts desc);
create index if not exists pushwarden_events_machine on public.pushwarden_events (machine_id, ts desc);
create index if not exists pushwarden_events_kind    on public.pushwarden_events (kind, sev, category);

-- ── access: the machines' key may insert, nothing else ──────────────────────

alter table public.pushwarden_events enable row level security;

-- Supabase grants the API roles everything on new tables; take that back and
-- hand out the one thing an upload needs.
revoke all on public.pushwarden_events from anon, authenticated;
grant insert on public.pushwarden_events to anon;

drop policy if exists "machines may insert" on public.pushwarden_events;
create policy "machines may insert" on public.pushwarden_events
    for insert to anon with check (true);
-- No other policy: with row level security on, that means no reading,
-- changing or deleting through the API.

-- A machine sends a batch again when the answer to the first attempt was
-- lost. Rows that are already stored are skipped here, so the retry succeeds
-- and stores nothing twice. ("insert ... on conflict do nothing" cannot be
-- used for this: Postgres only allows it to roles that may read the table.)
create or replace function public.pushwarden_skip_duplicate() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
    if exists (select 1 from public.pushwarden_events where event_id = new.event_id) then
        return null;
    end if;
    return new;
end $$;
revoke all on function public.pushwarden_skip_duplicate() from public, anon, authenticated;

drop trigger if exists pushwarden_skip_duplicate on public.pushwarden_events;
create trigger pushwarden_skip_duplicate before insert on public.pushwarden_events
    for each row execute function public.pushwarden_skip_duplicate();

-- ── views for triage (read them as the project owner) ───────────────────────
-- security_invoker makes a view obey the table's row level security for
-- whoever queries it, and the revoke below closes the views to the API roles.
-- Without both, a view would hand the whole table to the machines' key.

-- What users said was wrong: dialog answers "keep" and explicit false-positive reports.
create or replace view public.pushwarden_false_positive_signals
with (security_invoker = true) as
select e.ts, e.machine_id, e.ver, e.iocs, e.kind, e.action, e.category, e.title, e.path, e.note
from public.pushwarden_events e
where e.kind = 'feedback'
   or (e.kind = 'decision' and e.action = 'keep')
order by e.ts desc;

-- Distinct findings and how widely each is seen. A finding on one machine only hints at a false positive.
create or replace view public.pushwarden_findings_summary
with (security_invoker = true) as
select category, sev, threat, matched,
       count(*)                                        as sightings,
       count(distinct machine_id)                      as machines,
       min(ts)                                         as first_seen,
       max(ts)                                         as last_seen,
       count(*) filter (where action like '%failed%')  as failed_responses
from public.pushwarden_events
where kind = 'finding'
group by category, sev, threat, matched
order by last_seen desc;

-- Things PushWarden itself got wrong: failed actions, panics, refused or rolled-back updates.
create or replace view public.pushwarden_tool_errors
with (security_invoker = true) as
select ts, machine_id, ver, os, kind, category, title, action, note
from public.pushwarden_events
where kind = 'error'
   or (kind = 'action' and ok = false)
   or (kind = 'finding' and action like '%failed%')
order by ts desc;

-- Fleet health: last contact, version and sweep time per machine.
create or replace view public.pushwarden_machines
with (security_invoker = true) as
select machine_id,
       max(ts)                                as last_event,
       max(received_at)                       as last_upload,
       (array_agg(ver  order by ts desc) filter (where ver  <> ''))[1] as version,
       (array_agg(os   order by ts desc) filter (where os   <> ''))[1] as os,
       (array_agg(iocs order by ts desc) filter (where iocs <> ''))[1] as indicators,
       round(avg((data->>'seconds')::numeric)
             filter (where kind = 'sweep' and data->>'phase' = 'end' and data->>'seconds' ~ '^[0-9.]+$')) as avg_sweep_seconds
from public.pushwarden_events
group by machine_id
order by last_event desc;

revoke all on public.pushwarden_false_positive_signals,
              public.pushwarden_findings_summary,
              public.pushwarden_tool_errors,
              public.pushwarden_machines
    from anon, authenticated;
