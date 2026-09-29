-- 하루 일기 — 동기화 키 방식 Supabase 설정
-- Supabase 대시보드 → SQL Editor 에 전체를 붙여 넣고 Run.
--
-- 구조: 테이블은 RLS로 완전히 잠그고(정책 없음), 동기화 키를 받는 두 함수로만 접근.
--       키 원문은 저장하지 않고 SHA-256 해시(space)로만 구분.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.haru_entries (
  space     text        not null,               -- sha256(동기화 키)
  id        text        not null,               -- 일기 id (e1759040000000)
  data      jsonb       not null default '{}',  -- 일기 전체 (그림 포함)
  updated   timestamptz not null,               -- 기기에서 마지막으로 고친 시각
  deleted   boolean     not null default false, -- 삭제 표시 (다른 기기에 전파용)
  synced_at timestamptz not null default clock_timestamp(),
  primary key (space, id)
);
create index if not exists haru_entries_sync_idx on public.haru_entries (space, synced_at, id);

alter table public.haru_entries enable row level security;
-- 정책을 만들지 않음 → anon 키로 테이블 직접 조회·수정 불가
revoke all on public.haru_entries from anon, authenticated;

create or replace function public.haru_space(p_key text)
returns text language plpgsql immutable
set search_path = public, extensions as $$
begin
  if length(coalesce(p_key, '')) < 24 then
    raise exception 'sync key too short';
  end if;
  return encode(extensions.digest(p_key, 'sha256'), 'hex');
end $$;

-- 받아오기: 커서(synced_at, id) 이후 변경분을 50개씩
create or replace function public.haru_pull(p_key text, p_since timestamptz default null, p_after_id text default '')
returns table (id text, data jsonb, updated timestamptz, deleted boolean, synced_at timestamptz)
language plpgsql security definer
set search_path = public, extensions as $$
declare s text := haru_space(p_key);
begin
  return query
    select e.id, e.data, e.updated, e.deleted, e.synced_at
    from haru_entries e
    where e.space = s
      and (p_since is null or (e.synced_at, e.id) > (p_since, coalesce(p_after_id, '')))
    order by e.synced_at, e.id
    limit 50;
end $$;

-- 올리기: 더 최신(updated)일 때만 덮어씀
create or replace function public.haru_push(p_key text, p_rows jsonb)
returns integer
language plpgsql security definer
set search_path = public, extensions as $$
declare s text := haru_space(p_key); n integer;
begin
  insert into haru_entries as t (space, id, data, updated, deleted, synced_at)
  select s, r->>'id', coalesce(r->'data', '{}'::jsonb), (r->>'updated')::timestamptz,
         coalesce((r->>'deleted')::boolean, false), clock_timestamp()
  from jsonb_array_elements(p_rows) r
  where r->>'id' is not null and r->>'updated' is not null
  on conflict (space, id) do update
    set data = excluded.data, updated = excluded.updated,
        deleted = excluded.deleted, synced_at = clock_timestamp()
    where t.updated < excluded.updated;
  get diagnostics n = row_count;
  return n;
end $$;

revoke all on function public.haru_space(text) from public, anon, authenticated;
revoke all on function public.haru_pull(text, timestamptz, text) from public;
revoke all on function public.haru_push(text, jsonb) from public;
grant execute on function public.haru_pull(text, timestamptz, text) to anon, authenticated;
grant execute on function public.haru_push(text, jsonb) to anon, authenticated;
