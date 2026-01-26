import json
import os
import tempfile

import pytest

import bannedfuncdetector.infrastructure.config_repository as config_module


@pytest.fixture
def reset_config():
    """Fixture to save and restore CONFIG state after each test."""
    original = config_module.CONFIG.to_dict()
    yield
    config_module.CONFIG._update_internal(original)


def test_load_config_missing_file(tmp_path, reset_config):
    missing = tmp_path / "missing.json"
    result = config_module.load_config(str(missing))
    # Should return default config when file is missing
    assert isinstance(result, dict)
    assert "decompiler" in result
    assert "output" in result


def test_load_config_updates_nested(tmp_path, reset_config):
    cfg = {
        "decompiler": {
            "type": "r2dec",
            "options": {
                "default": {"enabled": False},
                "r2dec": {"command": "pdd"},
            },
        },
        "output": {"directory": "out"},
        "new_key": "value",
    }
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg))
    result = config_module.load_config(str(cfg_path))
    # Should return the merged config dict
    assert isinstance(result, dict)
    assert result["decompiler"]["type"] == "r2dec"
    assert config_module.CONFIG["decompiler"]["type"] == "r2dec"
    assert config_module.CONFIG["decompiler"]["options"]["default"]["enabled"] is False
    assert config_module.CONFIG["output"]["directory"] == "out"
    assert config_module.CONFIG["new_key"] == "value"


def test_load_config_adds_new_subkeys(tmp_path, reset_config):
    cfg = {
        "decompiler": {
            "new_group": {"enabled": True},
            "options": {
                "default": {"new_option": True},
                "new_section": {"enabled": True},
            }
        }
    }
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg))
    result = config_module.load_config(str(cfg_path))
    # Should return the merged config dict
    assert isinstance(result, dict)
    assert config_module.CONFIG["decompiler"]["options"]["default"]["new_option"] is True
    assert config_module.CONFIG["decompiler"]["options"]["new_section"]["enabled"] is True
    assert config_module.CONFIG["decompiler"]["new_group"]["enabled"] is True


def test_load_config_invalid_json(tmp_path, reset_config):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text("{invalid json")
    result = config_module.load_config(str(cfg_path))
    # Should return default config when JSON is invalid
    assert isinstance(result, dict)
    assert "decompiler" in result
    assert "output" in result
