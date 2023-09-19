# LDAP SQL Adapter

An LDAP server that uses an already existing SQL database as backend.

## Why?

I created this so that I could use my existing PostgreSQL database as a backend for authelia.

## Configuration

The configuration is done via command line flags or environment variables.

| Command Line Flag                           | Environment Variable                      | Default Value       | Description                                                                                |
| ------------------------------------------- | ----------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------ |
| `--env`                                     | `GO_ENV`                                  | `development`       | The environment in which the application is running. Decides which .env.{env} file to load |
| `--log-level`                               | `LOG_LEVEL`                               | `info`              | The log level for the application                                                          |
| `--config`                                  | `CONFIG`                                  | N/A                 | The path to the configuration file                                                         |
| `--host`                                    | `HOST`                                    | `localhost`         | The host on which the application should listen                                            |
| `--http-port`                               | `HTTP_PORT`                               | `4181`              | The port on which the application should listen for HTTP requests                          |
| `--ldap-port`                               | `LDAP_PORT`                               | `10389`             | The port on which the application should listen for LDAP requests                          |
| `--bind-username`                           | `BIND_USERNAME`                           | `admin`             | The username for the LDAP bind operation                                                   |
| `--bind-password`                           | `BIND_PASSWORD`                           | `admin`             | The password for the LDAP bind operation                                                   |
| `--base-dn`                                 | `BASE_DN`                                 | `dc=example,dc=com` | The base DN for the LDAP search operation                                                  |
| `--database-url`                            | `DATABASE_URL`                            | N/A                 | The URL for the database connection                                                        |
| `--sql-get-user-password-by-username-query` | `SQL_GET_USER_PASSWORD_BY_USERNAME_QUERY` | `""`                | The SQL query to retrieve a user's password by their username                              |
| `--sql-get-user-by-username-or-email-query` | `SQL_GET_USER_BY_USERNAME_OR_EMAIL_QUERY` | `""`                | The SQL query to retrieve a user by their username or email                                |
| `--sql-get-user-groups-query`               | `SQL_GET_USER_GROUPS_QUERY`               | `""`                | The SQL query to retrieve a user's groups                                                  |
| `--sql-update-password-query`               | `SQL_UPDATE_PASSWORD_QUERY`               | `""`                | The SQL query to update a user's password                                                  |
