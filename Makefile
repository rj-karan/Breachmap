# Lab helpers. Everything except lab-apply/lab-destroy runs without an AWS account.
TF ?= terraform
TFDIR := lab/aws

.PHONY: check lab-plan lab-apply lab-destroy kind-up kind-down

check:
	uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest

# Plan the AWS lab offline (dummy credentials) and compare it with the fixture.
lab-plan:
	$(TF) -chdir=$(TFDIR) fmt -check -recursive
	$(TF) -chdir=$(TFDIR) init -backend=false -input=false >/dev/null
	$(TF) -chdir=$(TFDIR) validate
	AWS_ACCESS_KEY_ID=offline AWS_SECRET_ACCESS_KEY=offline \
	  $(TF) -chdir=$(TFDIR) plan -input=false -lock=false -refresh=false \
	  -var-file=offline.tfvars -out=lab.tfplan
	$(TF) -chdir=$(TFDIR) show -json lab.tfplan > $(TFDIR)/plan.json
	uv run pytest tests/lab/test_lab_sources.py -q --no-cov

# Real account only. Needs lab/aws/lab.auto.tfvars (see the .example file).
lab-apply:
	$(TF) -chdir=$(TFDIR) apply

lab-destroy:
	$(TF) -chdir=$(TFDIR) destroy

kind-up:
	kind create cluster --config lab/kind/cluster.yaml
	kubectl --context kind-breachmap-lab apply -f lab/kind/manifests/

kind-down:
	kind delete cluster --name breachmap-lab
