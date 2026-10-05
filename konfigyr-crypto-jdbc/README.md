# Konfigyr Crypto JDBC

The `konfigyr-crypto-jdbc` module provides `JdbcKeysetRepository`, a `KeysetRepository` that stores encrypted
keysets in a relational database through Spring's `JdbcTemplate`. Use it instead of the in-memory repository
whenever keysets must survive a restart.

This guide is for developers who set up the persistence of their keysets. It assumes that your application already
has a configured `DataSource`. It doesn't explain how to run database migrations for your own tables.

## Before you begin

Add the module and the Spring Boot JDBC starter to your application:

```kotlin
dependencies {
    implementation(platform("com.konfigyr:konfigyr-crypto-dependencies:1.1.0"))

    implementation("com.konfigyr:konfigyr-crypto-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
}
```

## Autoconfiguration

`JdbcKeysetAutoConfiguration` declares a `JdbcKeysetRepository` bean when all of the following are true:

- The application context contains a `DataSource` and a `PlatformTransactionManager` bean.
- The application context doesn't contain another `KeysetRepository` bean.

The `KeysetStore` and the [scheduled maintenance tasks](../README.md#scheduled-maintenance-tasks) then use this
repository. Every write runs in a transaction, and the repository uses the `KEYSET_VERSION` column for optimistic
locking.

## Create the tables

The repository uses two tables:

- `KEYSETS` stores one row per keyset: its name, purpose, factory, the provider and identifier of its key
  encryption key, its rotation interval, rotation lead time, destruction grace period, retirement policy, and
  version.
- `KEYSET_KEYS` stores one row per key: its identifier, algorithm, type, status, primary flag, the wrapped key
  material, and its lifecycle timestamps. Deleting a keyset row deletes its key rows.

Durations are stored in milliseconds and timestamps in epoch milliseconds, both as `BIGINT` columns. The key material
column only ever contains key material that the key encryption key has wrapped.

The module ships a schema script for each of the following databases: DB2, Derby, H2, HSQLDB, MySQL and MariaDB,
Oracle, PostgreSQL, SQLite, SQL Server, and Sybase. They're located in the module JAR under
`com/konfigyr/crypto/jdbc/schema-PLATFORM.sql`. A generic `schema-default.sql` script is included as well.

By default, the scripts only run against embedded databases. To create the tables in other databases, set the
initialization mode:

```properties
konfigyr.crypto.jdbc.initialize-schema=always
```

The initializer detects the platform from the `DataSource`. To choose the script yourself, set
`konfigyr.crypto.jdbc.platform`, for example to `postgresql` or `default`. Errors in the script, such as tables that
already exist, are ignored.

In production, consider creating the tables with your own migration tool, such as Flyway or Liquibase. Copy the
statements from the script for your database and set `konfigyr.crypto.jdbc.initialize-schema=never`.

## Configuration properties

The following table lists the properties under the `konfigyr.crypto.jdbc` prefix:

| Property | Default | Description |
|---|---|---|
| `initialize-schema` | `embedded` | When to run the schema script: `embedded`, `always`, or `never`. |
| `schema` | `classpath:com/konfigyr/crypto/jdbc/schema-@@platform@@.sql` | The location of the schema script. `@@platform@@` is replaced with the detected or configured platform. |
| `platform` | Detected from the `DataSource` | The platform name used to resolve the `@@platform@@` placeholder. |
| `keysets-table-name` | `KEYSETS` | The name of the keysets table. |
| `keys-table-name` | `KEYSET_KEYS` | The name of the keys table. |
| `transaction-isolation-level` | `DEFAULT` | The isolation level of the write transactions. |
| `transaction-propagation-behavior` | `REQUIRED` | The propagation behavior of the write transactions. |
| `transaction-timeout` | `30s` | The timeout of the write transactions. |

The `table-name` property is deprecated. Use `keysets-table-name` instead. When both are set, `keysets-table-name`
takes precedence.

## Use custom table names

To store the keysets in tables with other names, or in another schema, set the table name properties. The names can
be qualified with a schema, or with a catalog and a schema, and each part can be quoted with double quotes or
backticks:

```properties
konfigyr.crypto.jdbc.keysets-table-name=crypto.KEYSETS
konfigyr.crypto.jdbc.keys-table-name=crypto.KEYSET_KEYS
```

The repository concatenates the table names into its SQL statements, so it validates them when it starts and fails
for names that aren't valid SQL identifiers.

The bundled schema scripts always create the `KEYSETS` and `KEYSET_KEYS` tables. When you use other names, create the
tables yourself, or point the `schema` property to a script that uses your names.

## Customize the SQL statements

`JdbcKeysetRepository` has a setter for each of its SQL statements, for example `setGetKeysetQuery(...)` and
`setFindPendingRotationQuery(...)`, so that you can adapt them to your database. A custom statement can reference
the configured table names with the `%KEYSETS_TABLE_NAME%` and `%KEYS_TABLE_NAME%` placeholders. The `%TABLE_NAME%`
placeholder is deprecated and resolves to the keysets table name.

The statements aren't available as properties. To customize them, declare your own `JdbcKeysetRepository` bean,
which you construct with a `JdbcOperations` and a `TransactionOperations` object. As soon as you declare it, the
autoconfiguration backs off completely: it no longer creates the schema, and it no longer applies the
`konfigyr.crypto.jdbc` properties, so set the table names on your bean yourself.

Custom statements must select the same columns and bind the same parameters, in the same order, as the default
ones. The Javadoc of each setter describes its parameters. Pay attention to the following statements:

- The keyset create and update statements bind the rotation lead time and the retirement policy. Durations are bound
  in milliseconds, or as `NULL` when they aren't set.
- The keyset read statement and the pending rotation, preparation, and destruction queries select the
  `ROTATION_LEAD_TIME` and `RETIREMENT_POLICY` columns.
- The pending rotation query binds two parameters: the current time in epoch milliseconds and the primary flag
  `true`. The flag is a parameter because some databases, such as Oracle before 23ai, SQL Server, or Sybase, don't
  accept boolean literals.
- The pending preparation query binds three parameters: the current time in epoch milliseconds, `true` for the primary
  flag of the primary key, and `false` for the primary flag of the next key.

## What's next

- To configure the scheduled tasks that query this repository, see
  [Configure the tasks](../README.md#configure-the-tasks).
- To implement a repository for another storage, see the
  [repository contract](../konfigyr-crypto-api/README.md#keysetrepository).
