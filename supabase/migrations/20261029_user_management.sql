-- User management: profiles linked to Supabase Auth (auth.users).
-- Passwords live only in auth.users, managed by Supabase Auth. This table holds
-- the app's own details about each person: username, role, and whether they may sign in.

create schema if not exists private;

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  username text not null,
  email text not null,
  role text not null default 'member' check (role in ('admin', 'member')),
  active boolean not null default true,
  must_change_password boolean not null default false,
  created_at timestamptz not null default now(),
  constraint profiles_username_format check (username ~ '^[a-z0-9._-]{3,30}$')
);
create unique index profiles_username_key on public.profiles (lower(username));
create unique index profiles_email_key on public.profiles (lower(email));
alter table public.profiles enable row level security;

-- Helpers live in a schema the API does not expose. They run with owner rights so
-- policies can check a person's profile without recursing into the profiles policies.
create function private.is_member() returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (select 1 from public.profiles p where p.id = (select auth.uid()) and p.active);
$$;

create function private.is_admin() returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (select 1 from public.profiles p where p.id = (select auth.uid()) and p.active and p.role = 'admin');
$$;

revoke all on schema private from public, anon;
grant usage on schema private to authenticated;
revoke execute on function private.is_member(), private.is_admin() from public, anon;
grant execute on function private.is_member(), private.is_admin() to authenticated;

-- Profiles: people see their own row, admins see everyone. Creating users, changing
-- roles, deactivating and removing all go through the admin-users edge function.
create policy "read own profile" on public.profiles
  for select to authenticated using (id = (select auth.uid()));
create policy "admins read all profiles" on public.profiles
  for select to authenticated using ((select private.is_admin()));
create policy "update own password flag" on public.profiles
  for update to authenticated
  using (id = (select auth.uid())) with check (id = (select auth.uid()));

revoke all on public.profiles from anon;
revoke insert, update, delete on public.profiles from authenticated;
grant update (must_change_password) on public.profiles to authenticated;

-- Existing admin: the account already allowed to use the tracker.
insert into public.profiles (id, username, email, role)
select u.id, 'alohalohster', lower(u.email), 'admin'
from auth.users u
where lower(u.email) = 'alohalohster@gmail.com'
on conflict (id) do nothing;

-- Actions: any active profile can read and edit, replacing the old email allowlist.
drop policy "team can read actions" on public.actions;
drop policy "team can add actions" on public.actions;
drop policy "team can update actions" on public.actions;
drop policy "team can delete actions" on public.actions;

create policy "members can read actions" on public.actions
  for select to authenticated using ((select private.is_member()));
create policy "members can add actions" on public.actions
  for insert to authenticated with check ((select private.is_member()));
create policy "members can update actions" on public.actions
  for update to authenticated
  using ((select private.is_member())) with check ((select private.is_member()));
create policy "members can delete actions" on public.actions
  for delete to authenticated using ((select private.is_member()));

drop table public.team_members;
