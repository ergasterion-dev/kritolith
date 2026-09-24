-- Upgrading an existing data dir gives every pre-existing claims row
-- empty decl_pkg_dir/decl_receiver/decl_name (the DEFAULT '' below),
-- since this identity was never computed or stored before this
-- migration. No historical report can anchor a fingerprint match on
-- resolved declaration identity until it is re-run through the
-- pipeline and its claims re-grounded. This is the safe direction: it
-- can only cause a temporarily missed duplicate match, never a false
-- one. Worth flagging for anyone upgrading a production data dir.
ALTER TABLE claims ADD COLUMN decl_pkg_dir  TEXT NOT NULL DEFAULT '';
ALTER TABLE claims ADD COLUMN decl_receiver TEXT NOT NULL DEFAULT '';
ALTER TABLE claims ADD COLUMN decl_name     TEXT NOT NULL DEFAULT '';
