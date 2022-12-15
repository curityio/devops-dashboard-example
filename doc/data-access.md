# Data Access

This document provides some commands for working with the example setup's database.\
This can be useful when troubleshooting access denied issues due to user group claims.

## Preconfigured Users

The Docker deployment uses a postgres database that stores data for the Curity Identity Server.\
The schema and data are provided in a postgres dump called `data-backup.sql`

## Get Connected to the Database

When the Docker system is running, connect to the postgres docker container with this command:

```bash
docker exec -it dashboard-curity-data-1 bash
```

Then connect to the database:

```bash
export PGPASSWORD=Password1 && psql -h localhost 5432 -d idsvr -U postgres
```

## Query Users and Groups

Then query the shipped user accounts, and any you create via the DevOps dashboard:

```bash
select username, attributes from accounts;
```

## Backup New Users

After creating new users in the dashboard, create an updated database dump if required.\
This will ensure that your users still exist if you redeploy the system:

```bash
docker exec -it dashboard-curity-data-1 bash -c "export PGPASSWORD=Password1 && pg_dump -U postgres -d idsvr" > ./data-backup2.sql
```
