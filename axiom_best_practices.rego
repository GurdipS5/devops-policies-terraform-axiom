package axiom.terraform.best_practices

############################
# Metadata
############################

__rego_metadata__ := {
  "id": "AXIOM_TERRAFORM_BEST_PRACTICES",
  "title": "Axiom Terraform Best Practices",
  "severity": "high",
  "description": "Ensures secure, production-ready usage of Axiom in Terraform."
}

############################
# Helpers
############################

is_axiom_dataset(r) {
  r.type == "axiom_dataset"
}

is_axiom_token(r) {
  r.type == "axiom_token"
}

############################
# Rules
############################

# 1. Datasets must have descriptions
deny[msg] {
  r := input.resource_changes[_]
  is_axiom_dataset(r)
  not r.change.after.description

  msg := sprintf(
    "Axiom dataset '%s' must have a description",
    [r.name]
  )
}

# 2. Tokens must be ingest-only
deny[msg] {
  r := input.resource_changes[_]
  is_axiom_token(r)

  caps := r.change.after.capabilities[_]
  not caps.ingest

  msg := sprintf(
    "Axiom token '%s' must be ingest-only (no query/admin permissions)",
    [r.name]
  )
}

# 3. Tokens must be dataset-scoped
deny[msg] {
  r := input.resource_changes[_]
  is_axiom_token(r)

  caps := r.change.after.capabilities[_]
  count(caps.ingest) == 0

  msg := sprintf(
    "Axiom token '%s' must be scoped to at least one dataset",
    [r.name]
  )
}

# 4. Dataset naming convention
deny[msg] {
  r := input.resource_changes[_]
  is_axiom_dataset(r)

  not re_match("^(opnsense|tailscale)-logs$", r.change.after.name)

  msg := sprintf(
    "Axiom dataset '%s' must follow naming convention: opnsense-logs or tailscale-logs",
    [r.change.after.name]
  )
}

# 5. No hardcoded tokens
deny[msg] {
  r := input.resource_changes[_]
  is_axiom_token(r)

  r.change.after.token

  msg := sprintf(
    "Axiom token '%s' must not be hardcoded; use outputs and secrets management",
    [r.name]
  )
}

# 6. Provider token must be variable-driven
deny[msg] {
  p := input.configuration.provider_config.axiom[_]
  p.expressions.api_token.constant_value

  msg := "Axiom provider api_token must be supplied via variable or environment variable"
}
