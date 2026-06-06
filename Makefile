.PHONY: lint validate plan

lint:
	ruff check .

validate:
	cd terraform && terraform validate

plan:
	cd terraform/environments/dev && terraform plan -out=tfplan

fmt:
	cd terraform && terraform fmt -recursive
	ruff format .
