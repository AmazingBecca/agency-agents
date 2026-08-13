from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/publish-retained-evidence.yml").read_text(
    encoding="utf-8"
)


class PublisherWorkflowAmbientExecutionAuthorityTests(unittest.TestCase):
    def _publish_job_prefix(self) -> str:
        return WORKFLOW.split("  publish:\n", 1)[1].split("    steps:\n", 1)[0]

    def _source_fetch_step(self) -> str:
        return WORKFLOW.split(
            "      - name: Fetch exact public publisher source without caller credentials\n",
            1,
        )[1].split("      - uses: actions/setup-python@", 1)[0]

    def _git_init_index(self, fetch: str) -> int:
        return fetch.index('"$git_bin" init .')

    def _hardened_fetch_prefix(self) -> str:
        return (
            '"$git_bin" -c http.proxy= -c http.sslVerify=true '
            '-c protocol.allow=never -c protocol.https.allow=always '
            '-c credential.helper= -c http.extraHeader= fetch'
        )

    def test_job_neutralizes_shell_and_dynamic_loader_startup_authority(self) -> None:
        job = self._publish_job_prefix()
        for name in (
            "BASH_ENV",
            "ENV",
            "LD_PRELOAD",
            "LD_AUDIT",
            "LD_LIBRARY_PATH",
            "PYTHONHOME",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "NODE_OPTIONS",
            "NODE_PATH",
        ):
            self.assertIn(
                f"      {name}: ''\n",
                job,
                f"publisher job must neutralize inherited {name} before its first shell or executable",
            )

    def test_git_source_fetch_ignores_inherited_config_authority(self) -> None:
        job = self._publish_job_prefix()
        expected = {
            "GIT_CONFIG_NOSYSTEM": "'1'",
            "GIT_CONFIG_GLOBAL": "'/dev/null'",
            "GIT_CONFIG_SYSTEM": "'/dev/null'",
            "GIT_CONFIG_COUNT": "'0'",
            "GIT_CONFIG_PARAMETERS": "''",
        }
        for name, value in expected.items():
            self.assertIn(
                f"      {name}: {value}\n",
                job,
                f"publisher job must pin {name} before git init/fetch/checkout",
            )

    def test_git_init_cannot_inherit_template_hook_or_repository_redirection_authority(self) -> None:
        fetch = self._source_fetch_step()
        git_init = self._git_init_index(fetch)
        before_init = fetch[:git_init]
        self.assertIn(
            "unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY "
            "GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_TEMPLATE_DIR",
            before_init,
        )
        self.assertIn(
            'template_dir="$RUNNER_TEMP/intelligence-os-empty-git-template"',
            before_init,
        )
        self.assertIn('mkdir -m 0700 "$template_dir"', before_init)
        self.assertIn('export GIT_TEMPLATE_DIR="$template_dir"', before_init)
        self.assertIn("test ! -e .git/hooks", fetch[git_init:])

    def test_git_fetch_cannot_inherit_exec_or_prompt_helper_authority(self) -> None:
        fetch = self._source_fetch_step()
        before_init = fetch[: self._git_init_index(fetch)]
        self.assertIn(
            "export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'",
            before_init,
        )
        self.assertIn(
            "unset GIT_EXEC_PATH GIT_ASKPASS SSH_ASKPASS GIT_SSH GIT_SSH_COMMAND GIT_PROXY_COMMAND",
            before_init,
        )
        self.assertIn("export GIT_ASKPASS=/bin/false", before_init)
        self.assertIn("export SSH_ASKPASS=/bin/false", before_init)
        self.assertIn("git_bin=/usr/bin/git", before_init)
        self.assertIn(
            'test "$(stat -c \'%u:%g:%a\' "$git_bin")" = "0:0:755"',
            before_init,
        )
        for command in (
            '"$git_bin" init .',
            '"$git_bin" remote add origin',
            self._hardened_fetch_prefix(),
            '"$git_bin" checkout --detach FETCH_HEAD',
            '"$git_bin" rev-parse HEAD',
            '"$git_bin" remote get-url origin',
        ):
            self.assertIn(command, fetch)

    def test_git_https_remote_helper_is_root_owned_and_not_runner_writable(self) -> None:
        fetch = self._source_fetch_step()
        before_init = fetch[: self._git_init_index(fetch)]
        self.assertIn('git_exec_path="$("$git_bin" --exec-path)"', before_init)
        self.assertIn('git_exec_path="$(realpath -e -- "$git_exec_path")"', before_init)
        self.assertIn('test "$(stat -c \'%u:%g\' "$git_exec_path")" = "0:0"', before_init)
        self.assertIn('git_exec_mode="$(stat -c \'%a\' "$git_exec_path")"', before_init)
        self.assertIn('(( (8#$git_exec_mode & 0022) == 0 ))', before_init)
        self.assertIn(
            'remote_https="$(realpath -e -- "$git_exec_path/git-remote-https")"',
            before_init,
        )
        self.assertIn(
            'case "$remote_https" in "$git_exec_path"/*) ;; *) exit 1 ;; esac',
            before_init,
        )
        self.assertIn('test "$(stat -c \'%u:%g\' "$remote_https")" = "0:0"', before_init)
        self.assertIn('remote_https_mode="$(stat -c \'%a\' "$remote_https")"', before_init)
        self.assertIn('(( (8#$remote_https_mode & 0022) == 0 ))', before_init)
        self.assertIn('test -x "$remote_https"', before_init)

    def test_git_fetch_neutralizes_tls_proxy_and_protocol_authority(self) -> None:
        fetch = self._source_fetch_step()
        before_init = fetch[: self._git_init_index(fetch)]
        self.assertIn(
            "unset GIT_SSL_NO_VERIFY GIT_SSL_CAINFO GIT_SSL_CAPATH GIT_SSL_CERT GIT_SSL_KEY "
            "GIT_SSL_CERT_PASSWORD_PROTECTED GIT_SSL_VERSION GIT_SSL_CIPHER_LIST",
            before_init,
        )
        self.assertIn(
            "unset GIT_PROXY_SSL_CERT GIT_PROXY_SSL_KEY GIT_PROXY_SSL_CERT_PASSWORD_PROTECTED "
            "GIT_PROXY_SSL_CAINFO GIT_PROXY_SSL_CAPATH GIT_HTTP_PROXY_AUTHMETHOD",
            before_init,
        )
        self.assertIn(
            "unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY",
            before_init,
        )
        self.assertIn("unset CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR", before_init)
        self.assertIn("export GIT_ALLOW_PROTOCOL=https", before_init)
        self.assertIn("export GIT_PROTOCOL_FROM_USER=0", before_init)
        self.assertIn("-c http.proxy=", fetch)
        self.assertIn("-c http.sslVerify=true", fetch)
        self.assertIn("-c protocol.allow=never", fetch)
        self.assertIn("-c protocol.https.allow=always", fetch)

    def test_credential_scrub_still_precedes_git_repository_creation(self) -> None:
        fetch = self._source_fetch_step()
        self.assertLess(fetch.index("unset GITHUB_TOKEN GH_TOKEN"), self._git_init_index(fetch))
        self.assertIn("-c credential.helper= -c http.extraHeader= fetch", fetch)
        self.assertIn(self._hardened_fetch_prefix(), fetch)


if __name__ == "__main__":
    unittest.main()
