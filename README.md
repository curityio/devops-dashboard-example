# Devops Dashboard Example

A fast demo setup of the DevOps dashboard for the Curity Identity Server

## Prerequisites

First ensure that you have a `license.json` file with these features:

- Enterprise license (a trial license is fine)
- Dashboard enabled
- Access to 3 or more user groups 

Also ensure that docker and docker compose are installed on the local computer

## Deploy the System

Run the following script to deploy the Curity Identity Server and a SQL database in a small docker compose network:

```bash
./deploy.sh
```

## Use the Admin UI

Login at `https://localhost:6749/admin` with credentials `admin / Password1`.\
The DevOps dashboard permissions are configured here:

![Admin UI](doc/admin-ui.png)

## Use the DevOps Dashboard as a High Privilege User

Login at `https://localhost:6749/admin/dashboard` with any credentials `johndoe / Password1`.\
This account represents a high privilege user from a devops team:

![DevOps User](doc/dashboard-devops-user.png)

## Use the DevOps Dashboard as a Low Privilege User

Login at `https://localhost:6749/admin/dashboard` with any credentials `janedoe / Password1`.\
This account represents a low privilege user from a devlopment team, who can only view OAuth clients:

![Developer User](doc/dashboard-developer-user.png)

## Website Documentation

See the [DevOps Dashboard](https://curity.io/resources/learn/devops-dashboard) tutorial for step by step instructions to get up and running.

## More Information

Please visit [curity.io](https://curity.io/) for more information about the Curity Identity Server.

