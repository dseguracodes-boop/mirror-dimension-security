from deception.decoy_secrets import DecoySecretGenerator


def test_generate_aws_keys():
    keys = DecoySecretGenerator.generate_aws_key_pair("test")
    assert "AWS_ACCESS_KEY_ID" in keys
    assert "AWS_SECRET_ACCESS_KEY" in keys
    assert keys["AWS_ACCESS_KEY_ID"].startswith("AKIATEST")
    assert len(keys["AWS_SECRET_ACCESS_KEY"]) > 20


def test_generate_postgres_uri():
    uri = DecoySecretGenerator.generate_postgres_uri("app_db")
    assert uri.startswith("postgresql://admin:pg_sec_")
    assert "/app_db" in uri


def test_generate_api_keys():
    openai_key = DecoySecretGenerator.generate_api_key("openai")
    github_key = DecoySecretGenerator.generate_api_key("github")

    assert openai_key.startswith("-".join(["sk", "proj", "canary"]) + "-")
    assert github_key.startswith("".join(["ghp", "_canary_"]))
