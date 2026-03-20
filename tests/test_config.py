import json


import bannedfuncdetector.infrastructure.config_repository as config_module


def test_load_config_missing_file(tmp_path):
    missing = tmp_path / "missing.json"
    result = config_module.load_config(str(missing))
    # Should return default config when file is missing
    assert isinstance(result, dict)
    assert "decompiler" in result
    assert "output" in result


def test_load_config_updates_nested(tmp_path):
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
    assert result["decompiler"]["options"]["default"]["enabled"] is False
    assert result["output"]["directory"] == "out"
    assert result["new_key"] == "value"


def test_load_config_adds_new_subkeys(tmp_path):
    cfg = {
        "decompiler": {
            "new_group": {"enabled": True},
            "options": {
                "default": {"new_option": True},
                "new_section": {"enabled": True},
            },
        }
    }
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg))
    result = config_module.load_config(str(cfg_path))
    # Should return the merged config dict
    assert isinstance(result, dict)
    assert result["decompiler"]["options"]["default"]["new_option"] is True
    assert result["decompiler"]["options"]["new_section"]["enabled"] is True
    assert result["decompiler"]["new_group"]["enabled"] is True


def test_load_config_invalid_json(tmp_path):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text("{invalid json")
    result = config_module.load_config(str(cfg_path))
    # Should return default config when JSON is invalid
    assert isinstance(result, dict)
    assert "decompiler" in result
    assert "output" in result
