-- v8: how many of an image's layers its verified annotated base digest provides
-- (docs/adr/0023-fixable-by-rebuild.md); 0 when unknown, as for inspections recorded before.
ALTER TABLE image_inspections ADD COLUMN annotated_base_layers INTEGER NOT NULL DEFAULT 0;
