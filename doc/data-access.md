# Data Access

This document provides some commands for working with the example setup's database.\
This can be useful when you want to view groups and other attributes stored against user accounts.

## Shipped Users

The Docker deployment uses a postgres database as a default data source for the Curity Identity Server.\
The schema and user accounts are provided in a postgres dump called `data-backup.sql`.

## Connect to the Database

When the Docker system is running, connect to the postgres docker container with this command:

```bash
docker exec -it dashboard-curity-data-1 bash
```

Then connect to the database:

```bash
export PGPASSWORD=Password1 && psql -h localhost 5432 -d idsvr -U postgres
```

## Query Users and their Groups

Then query the shipped user accounts, and any you create via the DevOps dashboard:

```bash
select username, attributes from accounts;
```

## Backup New Users

After creating new users in the dashboard, back them up if required.\
This will ensure that your users still exist if you redeploy the system:
Run the following command from the host computer, to create the backup:

```bash
docker exec -it dashboard-curity-data-1 bash -c "export PGPASSWORD=Password1 && pg_dump -U postgres -d idsvr" > ./data-backup.sql
```
