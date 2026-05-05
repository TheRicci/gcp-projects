# Terraform

Terraform owns the GCP substrate for the lab:

- VPC and subnet
- firewall rules
- one Compute Engine VM
- VM service account and IAM
- Pub/Sub topics

It intentionally does not manage Docker Compose services, Suricata rules, Zeek scripts, or honeypot application behavior.

Start in `terraform/`.

```powershell
Copy-Item terraform/terraform.tfvars.example terraform/terraform.tfvars
terraform -chdir=terraform init
terraform -chdir=terraform plan
terraform -chdir=terraform apply
```
