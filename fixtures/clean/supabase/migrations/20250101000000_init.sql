-- ShipNotes schema: RLS on every table, owner-only policies.
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  display_name text
);
alter table public.profiles enable row level security;
create policy "Users read their own profile" on public.profiles for select using (auth.uid() = id);
create policy "Users update their own profile" on public.profiles for update using (auth.uid() = id) with check (auth.uid() = id);

create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references auth.users,
  title text not null,
  body text not null default ''
);
alter table public.notes enable row level security;
create policy "Users manage their own notes" on public.notes for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
