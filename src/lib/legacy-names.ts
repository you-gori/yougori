// Names from before the product was renamed to Yougori. Existing installs saved data
// under them; they are kept only so that data can still be found and moved, and
// nothing new is written under them. Remove once supported upgrades no longer start
// from releases that used them. The Rust equivalent is cli/src/legacy_names.rs.

/** Prefix of browser preferences saved by earlier releases. */
export const PREFERENCE_PREFIX = "opendock."

/** File extension of local backups made by earlier releases. */
export const BACKUP_EXTENSION = "opendock"
