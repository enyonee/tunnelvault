"""Tests for tv.i18n: locale detection, translation, key parity."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tv import i18n
from tv.lang import en, ru


@pytest.fixture(autouse=True)
def _reset_i18n():
    """Reset i18n state between tests."""
    i18n.reset()
    yield
    i18n.reset()
    i18n.init("en")  # restore default for other tests


class TestDetectLocale:
    def test_lc_all_ru(self):
        with patch.dict("os.environ", {"LC_ALL": "ru_RU.UTF-8"}, clear=False):
            i18n.reset()
            i18n.init()
            assert i18n.current() == "ru"

    def test_lc_all_en(self):
        with patch.dict("os.environ", {"LC_ALL": "en_US.UTF-8"}, clear=False):
            i18n.reset()
            i18n.init()
            assert i18n.current() == "en"

    def test_lang_ru(self):
        env = {"LC_ALL": "", "LC_MESSAGES": "", "LANG": "ru_RU.UTF-8"}
        with patch.dict("os.environ", env, clear=False):
            i18n.reset()
            i18n.init()
            assert i18n.current() == "ru"

    def test_c_locale_defaults_to_en(self):
        env = {"LC_ALL": "C", "LC_MESSAGES": "", "LANG": ""}
        with patch.dict("os.environ", env, clear=False):
            i18n.reset()
            i18n.init()
            assert i18n.current() == "en"

    def test_posix_locale_defaults_to_en(self):
        env = {"LC_ALL": "POSIX", "LC_MESSAGES": "", "LANG": ""}
        with patch.dict("os.environ", env, clear=False):
            i18n.reset()
            i18n.init()
            assert i18n.current() == "en"

    def test_explicit_init_overrides_env(self):
        with patch.dict("os.environ", {"LC_ALL": "ru_RU.UTF-8"}, clear=False):
            i18n.init("en")
            assert i18n.current() == "en"


class TestTranslate:
    def test_en_translation(self):
        i18n.init("en")
        assert i18n.t("ui.not_set") == "not set"

    def test_ru_translation(self):
        i18n.init("ru")
        assert i18n.t("ui.not_set") == "не задано"

    def test_format_params(self):
        i18n.init("en")
        result = i18n.t("main.log_colon", path="/tmp/test.log")
        assert result == "Log: /tmp/test.log"

    def test_missing_key_returns_key(self):
        i18n.init("en")
        assert i18n.t("nonexistent.key") == "nonexistent.key"

    def test_lazy_init_on_first_call(self):
        """t() triggers auto-init if not initialized."""
        i18n.reset()
        with patch.dict("os.environ", {"LC_ALL": "en_US.UTF-8"}, clear=False):
            result = i18n.t("ui.not_set")
        assert result == "not set"
        assert i18n.current() == "en"


class TestKeyParity:
    def test_en_and_ru_have_same_keys(self):
        """Both language files must have identical key sets."""
        en_keys = set(en.STRINGS.keys())
        ru_keys = set(ru.STRINGS.keys())

        missing_in_ru = en_keys - ru_keys
        missing_in_en = ru_keys - en_keys

        errors = []
        if missing_in_ru:
            errors.append(f"Missing in ru.py: {sorted(missing_in_ru)}")
        if missing_in_en:
            errors.append(f"Missing in en.py: {sorted(missing_in_en)}")

        assert not errors, "\n".join(errors)

    def test_no_empty_values(self):
        """No empty string values in either language."""
        for key, val in en.STRINGS.items():
            assert val, f"en.py: empty value for '{key}'"
        for key, val in ru.STRINGS.items():
            assert val, f"ru.py: empty value for '{key}'"
