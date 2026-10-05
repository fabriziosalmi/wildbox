"""The sensor's data-lake settings are validated when it starts (#628).

The destination is the gateway over HTTPS, the credential an identity API key,
and the TLS trust either the system store or a CA bundle. A setting that
cannot work stops the sensor with a message naming it; only a missing key is
tolerated, because the key cannot exist before the stack has started.
"""

import sys
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.core.config import DataLakeConfig, load_config  # noqa: E402

API_KEY = "wsk_t3st.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

ENV = (
    "SENSOR_DATA_LAKE_ENDPOINT",
    "SENSOR_DATA_LAKE_API_KEY",
    "SENSOR_DATA_LAKE_TLS_VERIFY",
    "SENSOR_DATA_LAKE_CA_BUNDLE",
    "SENSOR_DATA_LAKE_SENSOR_ID",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ENV:
        monkeypatch.delenv(name, raising=False)


def _errors(**fields):
    settings = {"endpoint": "https://gateway.example", "api_key": API_KEY}
    settings.update(fields)
    return DataLakeConfig(**settings).validate()


def test_the_gateway_url_is_valid_and_gets_the_ingest_path():
    config = DataLakeConfig(endpoint="https://gateway.example/", api_key=API_KEY)

    assert config.validate() == []
    assert config.ingest_url == "https://gateway.example/api/v1/data/ingest"


def test_the_full_ingest_url_is_kept():
    config = DataLakeConfig(
        endpoint="https://gateway.example:8443/api/v1/data/ingest", api_key=API_KEY
    )

    assert config.validate() == []
    assert config.ingest_url == "https://gateway.example:8443/api/v1/data/ingest"


def test_plain_http_is_refused():
    (error,) = _errors(endpoint="http://open-security-gateway")

    assert "https://" in error


def test_the_old_direct_data_service_url_is_refused_with_a_pointer():
    (error,) = _errors(endpoint="https://open-security-data:8002/api/v1/ingest")

    assert "/api/v1/ingest" in error
    assert "UPGRADING.md" in error


def test_a_missing_endpoint_is_refused():
    (error,) = _errors(endpoint="")

    assert "data_lake.endpoint is required" in error


def test_a_key_that_is_not_an_identity_key_is_refused():
    (error,) = _errors(api_key="the-old-data-service-api-key")

    assert "wsk_" in error


@pytest.mark.parametrize("unset", ["", "CONFIGURE_VIA_ENV", "your-api-key-here"])
def test_a_missing_key_disables_forwarding_without_an_error(unset):
    config = DataLakeConfig(endpoint="https://gateway.example", api_key=unset)

    assert config.validate() == []
    assert config.forwarding_enabled is False


def test_a_missing_ca_bundle_is_refused(tmp_path):
    (error,) = _errors(ca_bundle=str(tmp_path / "absent.crt"))

    assert "does not exist" in error


def test_a_ca_bundle_with_verification_off_is_refused(tmp_path):
    bundle = tmp_path / "gateway.crt"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")

    (error,) = _errors(ca_bundle=str(bundle), tls_verify=False)

    assert "tls_verify" in error


def _write(tmp_path, data_lake):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"data_lake": data_lake}))
    return str(path)


def test_verification_stays_on_when_the_file_does_not_mention_it(tmp_path):
    config = load_config(_write(tmp_path, {"endpoint": "https://gw.example"}))

    assert config.data_lake.tls_verify is True


def test_the_environment_sets_the_gateway_key_and_bundle(tmp_path, monkeypatch):
    bundle = tmp_path / "gateway.crt"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    monkeypatch.setenv("SENSOR_DATA_LAKE_ENDPOINT", "https://open-security-gateway")
    monkeypatch.setenv("SENSOR_DATA_LAKE_API_KEY", API_KEY)
    monkeypatch.setenv("SENSOR_DATA_LAKE_CA_BUNDLE", str(bundle))
    monkeypatch.setenv("SENSOR_DATA_LAKE_SENSOR_ID", "edge-1")

    config = load_config(_write(tmp_path, {"endpoint": "https://elsewhere.example"}))

    assert (
        config.data_lake.ingest_url
        == "https://open-security-gateway/api/v1/data/ingest"
    )
    assert config.data_lake.api_key == API_KEY
    assert config.data_lake.ca_bundle == str(bundle)
    assert config.data_lake.sensor_id == "edge-1"
    assert config.data_lake.forwarding_enabled is True


def test_empty_compose_variables_mean_unset(tmp_path, monkeypatch):
    # docker-compose.yml passes ${VAR:-}, so an unset variable arrives empty.
    monkeypatch.setenv("SENSOR_DATA_LAKE_API_KEY", "")
    monkeypatch.setenv("SENSOR_DATA_LAKE_CA_BUNDLE", "")

    config = load_config(_write(tmp_path, {"endpoint": "https://gw.example"}))

    assert config.data_lake.ca_bundle is None
    assert config.data_lake.forwarding_enabled is False


def test_an_invalid_setting_stops_the_sensor(tmp_path):
    with pytest.raises(ValueError, match="https://"):
        load_config(
            _write(
                tmp_path, {"endpoint": "http://open-security-data:8002/api/v1/ingest"}
            )
        )


@pytest.mark.parametrize(
    "shipped", ["config.yaml.example", "config.yaml", "config.docker.yaml"]
)
def test_the_shipped_configurations_load(shipped, tmp_path, monkeypatch):
    # The container's configurations name the container's data directory,
    # which the image creates; here it is this test's.
    monkeypatch.setenv("SENSOR_DATA_DIR", str(tmp_path))
    config = load_config(str(SERVICE_ROOT / shipped))

    assert config.data_lake.tls_verify is True
    assert config.data_lake.ingest_url.endswith("/api/v1/data/ingest")
    assert config.data_lake.ingest_url.startswith("https://")
