-- ShipNotes schema
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  email text,
  role text default 'user'
);
alter table public.profiles enable row level security;
create policy "Profiles are editable by everyone" on public.profiles for all using (true) with check (true);

create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users,
  title text,
  body text
);

create table public.payments (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users,
  card_number text,
  cvv text,
  amount integer
);
