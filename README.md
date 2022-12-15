# Devops Dashboard Example

A fast demo setup of the DevOps dashboard for the Curity Identity Server

## Prerequisites

First ensure that you have a `license.json` file with these features:

- Enterprise license (a trial license is fine)
- Dashboard feature enabled
- Access to 3 or more user groups 

Also ensure that docker and docker compose are installed on the local computer.

## Deploy the System

Clone this repository, then copy the license.json file into the root folder.\
Run the script to deploy the Curity Identity Server and a SQL database, in a small docker compose network:

```bash
./deploy.sh
```

## Use the Admin UI

Login at https://localhost:6749/admin with credentials `admin / Password1`.\
The administration permissions for each team is configured under `System / Administrators / DevOps`:

![Admin UI](doc/admin-ui.png)

## Use the DevOps Dashboard as a High Privilege User

Login at `https://localhost:6749/admin/dashboard` with the credentials `johndoe / Password1`.\
This account represents a high privilege user from a DevOps team:

![DevOps User](doc/devops-user-access.png)

## Use the DevOps Dashboard as a Low Privilege User

Login at `https://localhost:6749/admin/dashboard` with the credentials `janedoe / Password1`.\
This account represents a low privilege user from a devlopment team, who can only edit OAuth clients:

![Developer User](doc/developer-user-access.png)

## Website Documentation

See the [DevOps Dashboard](https://curity.io/resources/learn/devops-dashboard) tutorial for a step by step walkthrough.\
This starts with an empty docker installation, with only the built-in `admin` user account.\
It then shows how to migrate administration to employee user accounts stored in a data source.

## Technical Details

For further information on technical aspects of the example setup, and to troubleshoot, see these pages:

- [OAuth Flow](doc/oauth-flow.md)
- [Data Access](doc/data-access.md)

## More Information

Please visit [curity.io](https://curity.io/) for more information about the Curity Identity Server.
