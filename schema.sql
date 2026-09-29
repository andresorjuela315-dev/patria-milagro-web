create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'driver' check (role in ('driver', 'admin')),
  email text not null default '',
  full_name text not null default '',
  identification text,
  phone text,
  company text,
  vehicle_plate text,
  vehicle_type text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.profiles add column if not exists email text not null default '';

create table if not exists public.appointments (
  id uuid primary key default gen_random_uuid(),
  driver_id uuid references public.profiles(id) on delete set null,
  driver_name text,
  carrier_company text not null,
  vehicle_plate text,
  appointment_at timestamptz not null,
  operation_type text not null check (operation_type in ('loading', 'unloading')),
  dock text,
  status text not null default 'scheduled'
    check (status in ('scheduled', 'on_the_way', 'arrived', 'waiting', 'loading', 'unloading', 'completed', 'cancelled')),
  notes text,
  created_by uuid not null references auth.users(id),
  arrived_at timestamptz,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists appointments_driver_time_idx
  on public.appointments (driver_id, appointment_at);
create index if not exists appointments_time_status_idx
  on public.appointments (appointment_at, status);

create or replace function public.is_patria_admin()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1 from public.profiles
    where id = (select auth.uid()) and role = 'admin'
  );
$$;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  insert into public.profiles (id, email, full_name, identification, phone, company, vehicle_plate, vehicle_type)
  values (
    new.id,
    coalesce(new.email, ''),
    coalesce(new.raw_user_meta_data ->> 'full_name', ''),
    nullif(new.raw_user_meta_data ->> 'identification', ''),
    nullif(new.raw_user_meta_data ->> 'phone', ''),
    nullif(new.raw_user_meta_data ->> 'company', ''),
    nullif(upper(new.raw_user_meta_data ->> 'vehicle_plate'), ''),
    nullif(new.raw_user_meta_data ->> 'vehicle_type', '')
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_patria on auth.users;
create trigger on_auth_user_created_patria
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

insert into public.profiles (id, email, full_name, identification, phone, company, vehicle_plate, vehicle_type)
select
  users.id,
  coalesce(users.email, ''),
  coalesce(users.raw_user_meta_data ->> 'full_name', ''),
  nullif(users.raw_user_meta_data ->> 'identification', ''),
  nullif(users.raw_user_meta_data ->> 'phone', ''),
  nullif(users.raw_user_meta_data ->> 'company', ''),
  nullif(upper(users.raw_user_meta_data ->> 'vehicle_plate'), ''),
  nullif(users.raw_user_meta_data ->> 'vehicle_type', '')
from auth.users as users
on conflict (id) do nothing;

drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at
  before update on public.profiles
  for each row execute procedure public.set_updated_at();

drop trigger if exists appointments_set_updated_at on public.appointments;
create trigger appointments_set_updated_at
  before update on public.appointments
  for each row execute procedure public.set_updated_at();

create or replace function public.admin_save_appointment(
  p_id uuid,
  p_driver_id uuid,
  p_driver_name text,
  p_carrier_company text,
  p_vehicle_plate text,
  p_appointment_at timestamptz,
  p_operation_type text,
  p_dock text,
  p_notes text
)
returns uuid
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  saved_id uuid;
begin
  if not public.is_patria_admin() then
    raise exception 'Only company administrators can create or edit appointments.';
  end if;
  if p_operation_type not in ('loading', 'unloading') then
    raise exception 'Invalid operation type.';
  end if;
  if p_driver_id is not null and not exists (
    select 1 from public.profiles where id = p_driver_id and role = 'driver'
  ) then
    raise exception 'The selected profile is not a driver.';
  end if;

  if p_id is null then
    insert into public.appointments (
      driver_id, driver_name, carrier_company, vehicle_plate, appointment_at,
      operation_type, dock, notes, status, created_by
    )
    values (
      p_driver_id, nullif(p_driver_name, ''), p_carrier_company,
      nullif(upper(p_vehicle_plate), ''), p_appointment_at,
      p_operation_type, nullif(p_dock, ''), nullif(p_notes, ''),
      'scheduled', auth.uid()
    )
    returning id into saved_id;
  else
    update public.appointments
    set driver_id = p_driver_id,
        driver_name = nullif(p_driver_name, ''),
        carrier_company = p_carrier_company,
        vehicle_plate = nullif(upper(p_vehicle_plate), ''),
        appointment_at = p_appointment_at,
        operation_type = p_operation_type,
        dock = nullif(p_dock, ''),
        notes = nullif(p_notes, '')
    where id = p_id
    returning id into saved_id;
    if saved_id is null then
      raise exception 'Appointment not found.';
    end if;
  end if;
  return saved_id;
end;
$$;

alter table public.profiles enable row level security;
alter table public.appointments enable row level security;

drop policy if exists "Users can read own profile or admins can read all" on public.profiles;
create policy "Users can read own profile or admins can read all"
  on public.profiles for select to authenticated
  using (id = (select auth.uid()) or (select public.is_patria_admin()));

drop policy if exists "Drivers can update own profile" on public.profiles;
create policy "Drivers can update own profile"
  on public.profiles for update to authenticated
  using (id = (select auth.uid()) and role = 'driver')
  with check (id = (select auth.uid()) and role = 'driver');

drop policy if exists "Admins can update profiles" on public.profiles;
create policy "Admins can update profiles"
  on public.profiles for update to authenticated
  using ((select public.is_patria_admin()))
  with check ((select public.is_patria_admin()));

drop policy if exists "Drivers can read own appointments and admins can read all" on public.appointments;
create policy "Drivers can read own appointments and admins can read all"
  on public.appointments for select to authenticated
  using (driver_id = (select auth.uid()) or (select public.is_patria_admin()));

drop policy if exists "Admins can create appointments" on public.appointments;
create policy "Admins can create appointments"
  on public.appointments for insert to authenticated
  with check ((select public.is_patria_admin()) and created_by = (select auth.uid()));

drop policy if exists "Admins can update appointments" on public.appointments;
create policy "Admins can update appointments"
  on public.appointments for update to authenticated
  using ((select public.is_patria_admin()))
  with check ((select public.is_patria_admin()));

drop policy if exists "Drivers can update status of assigned appointments" on public.appointments;
create policy "Drivers can update status of assigned appointments"
  on public.appointments for update to authenticated
  using (driver_id = (select auth.uid()) and status not in ('completed', 'cancelled'))
  with check (driver_id = (select auth.uid()));

grant usage on schema public to authenticated;
grant execute on function public.is_patria_admin() to authenticated;
grant execute on function public.admin_save_appointment(uuid, uuid, text, text, text, timestamptz, text, text, text) to authenticated;
grant select on public.profiles, public.appointments to authenticated;
grant update (full_name, identification, phone, company, vehicle_plate, vehicle_type)
  on public.profiles to authenticated;
grant insert (
  driver_id, driver_name, carrier_company, vehicle_plate, appointment_at,
  operation_type, dock, notes, status, created_by
) on public.appointments to authenticated;
grant update (status, arrived_at, started_at, completed_at)
  on public.appointments to authenticated;

-- Replace this email with the first company administrator's Supabase login.
update public.profiles
set role = 'admin'
where id = (select id from auth.users where lower(email) = lower('admin@your-company.com'));
