from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "capability_lab.sh").read_text(encoding="utf-8")


def test_network_services_are_loopback_only():
    assert "--remote-debugging-address=127.0.0.1" in SOURCE
    assert "--ServerApp.ip=127.0.0.1" in SOURCE
    assert "-localhost -rfbport" in SOURCE
    assert "socket,host=127.0.0.1,port=" in SOURCE
    assert "-nolisten tcp" in SOURCE


def test_no_platform_supervisor_or_system_configuration_mutation():
    forbidden = (
        "supervisorctl",
        "/etc/supervisor",
        "/etc/systemd",
        "systemctl ",
        "service ",
        "CUA_DD_ENABLE_CHROME=true",
        "CUA_DD_INIT_",
    )
    for value in forbidden:
        assert value not in SOURCE


def test_authentication_is_ephemeral_and_not_committed():
    assert "secrets.token_urlsafe(20)" in SOURCE
    assert "secrets.token_urlsafe(32)" in SOURCE
    assert "-rfbauth \"$STATE/vnc.pass\"" in SOURCE
    assert "--ServerApp.token=\"$jupyter_token\"" in SOURCE
    assert "chmod 600 \"$STATE/env.sh\" \"$STATE/vnc.pass\"" in SOURCE


def test_ports_are_selected_dynamically():
    assert "bind(('127.0.0.1',0))" in SOURCE
    assert "AB_CAPLAB_CDP_PORT" in SOURCE
    assert "AB_CAPLAB_VNC_PORT" in SOURCE
    assert "AB_CAPLAB_JUPYTER_PORT" in SOURCE
    assert "AB_CAPLAB_LIBREOFFICE_PORT" in SOURCE


def test_manifest_binds_image_and_executable_state():
    assert "amazingbecca-capability-lab/v1" in SOURCE
    assert "CUA_DD_VM_BUILD" in SOURCE
    assert "CUA_DD_VM_COMMIT_SHA" in SOURCE
    assert "ACE_TOOLS_FEATURE_SET" in SOURCE
    assert "OPENAI_CLUSTER" in SOURCE
    assert "sha256" in SOURCE
    assert "product_gates" in SOURCE


def test_stop_path_is_explicit_and_reverse_ordered():
    assert 'tac "$STATE/pids"' in SOURCE
    assert 'kill "$pid"' in SOURCE
    assert 'kill -9 "$pid"' in SOURCE
