# GitHub Actions as an identity provider. AWS validates GitHub's certificate
# chain itself since 2023, but the resource still requires a thumbprint list;
# the documented GitHub values are used.
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://${local.github_host}"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"]
}

# Stand-in issuer for the kind cluster so IRSA-style trust can be expressed.
# Nothing can mint tokens for it; the irsa-app edge stays Derived (ADR-0002).
resource "aws_iam_openid_connect_provider" "kind" {
  url             = "https://${local.kind_host}"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["0000000000000000000000000000000000000000"]
}
