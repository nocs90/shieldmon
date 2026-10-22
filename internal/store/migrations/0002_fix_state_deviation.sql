-- v2: vendor fix state per finding ("won't fix" vs "no fix yet" vs "fixed") and
-- the policy deviation type of a decision. See docs/adr/0010-decision-policy.md.

ALTER TABLE findings ADD COLUMN fix_state TEXT NOT NULL DEFAULT 'unknown';

-- '' = plain risk acceptance within the remediation SLA,
-- 'vendor_dependency' = no vendor fix (won't fix / not yet fixed), re-reviewed monthly,
-- 'operational_requirement' = cannot be remediated for operational reasons.
ALTER TABLE decisions ADD COLUMN deviation TEXT NOT NULL DEFAULT '';
