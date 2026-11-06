# A synthetic 1.1.x installation

What a computer running Yougori 1.1.x keeps, for the migration dry run's tests
(`src-tauri/src/setups/migration/tests.rs`, plan 13.2 and 19.1). Every value is fake: example
names, `example.invalid` addresses, private test addresses and certificates marked as not real.
It was not copied from any computer.

- `data/` is the engine's data folder: a Neo Grid hub with its own membership and public link, a
  second Neo Grid (`grid/neo/i-0000a001/`) and one this computer only joined
  (`grid/neo/i-0000a002/`); a Sandbox Grid hub with this computer's membership, the desks it hosts,
  a person's sign-in and two prepared images, and a second desk grid (`grid/desks/i-0000d001/`);
  an Access Grid hub with this computer's sign-in, and a second one (`grid/access/i-0000c001/`).
- `home/.yougori/` is the CLI's folder: two v1 template instances, each as the CLI keeps it
  (`hub/records/NAME.json`) and as the desktop reads it (`hub/instances/NAME/instance.json`).

Nothing of Swarm Mining or bounties is here.

Each record was written by the product's own type. The hub records start from the grid crate's
frozen 1.1.2 fixtures (`grid/src/core/compat/frozen/`); the memberships, hosted desks, sign-in,
public link and instances were read into the application's own records and written back by them.

This is an old installation, so it is not rewritten when a type changes. The tests prove instead
that today's types read every file and keep every value in it. Write it again only on purpose:

```text
UPDATE_MIGRATION_FIXTURES=1 cargo test --manifest-path src-tauri/Cargo.toml --lib -- --skip swarm:: the_synthetic_installation_reads_with_each_products_own_types
```
