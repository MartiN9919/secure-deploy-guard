import pytest
from sdg.policy_engine.structural import StructuralGate, ApprovalRequiredError
from sdg.policy_engine.semantic import SemanticGate
from sdg.policy_engine.pii_mask import PIIMask
from sdg.policy_engine.context_hygiene import ContextHygiene



class TestStructuralGate:
    def setup_method(self):
        self.gate = StructuralGate({
            "environments": {"local": {"blocked_tools": ["destroy"], "required_approval": ["scan"]}},
            "roles": {"developer": {"allowed_tools": ["scan", "lint"], "except": ["delete"]}},
        })

    def test_allow_scan_developer_local(self):
        allowed, reason = self.gate.check_action_allowed("lint", role="developer", environment="local")
        assert allowed

    def test_block_destroy_in_local(self):
        allowed, reason = self.gate.check_action_allowed("destroy", role="developer", environment="local")
        assert not allowed
        assert "Blocked" in reason

    def test_block_excepted_tool(self):
        allowed, reason = self.gate.check_action_allowed("delete", role="developer", environment="local")
        assert not allowed
        assert "Excepted" in reason

    def test_required_approval_raises(self):
        from sdg.policy_engine.structural import ApprovalRequiredError
        with pytest.raises(ApprovalRequiredError):
            self.gate.check_action_allowed("scan", role="developer", environment="local")



class TestPIIMask:
    def test_mask_email(self):
        result = PIIMask.mask("contact me at test@example.com")
        assert "test@example.com" not in result
        assert "***@***.***" in result

    def test_mask_api_key(self):
        result = PIIMask.mask("key: sk-abc123def456ghi789jkl")
        assert "sk-" not in result

    def test_mask_finding_dict(self):
        d = {"message": "email: user@test.com", "file_path": "test.py"}
        masked = PIIMask.mask_finding(d)
        assert "user@test.com" not in masked["message"]
        assert "***@***.***" in masked["message"]
        assert masked["file_path"] == "test.py"


class TestContextHygiene:
    def test_resolve_context_from_env(self, monkeypatch):
        monkeypatch.setenv("MY_VAR", "hello")
        result = ContextHygiene.resolve("[[MY_VAR]]")
        assert result == "hello"

    def test_resolve_context_from_override(self):
        result = ContextHygiene.resolve("[[NAME]]", {"NAME": "world"})
        assert result == "world"

    def test_resolve_context_unresolved(self):
        result = ContextHygiene.resolve("[[UNKNOWN]]")
        assert result == "[[UNKNOWN]]"

    def test_context_hygiene_recursive(self):
        args = {"nested": {"email": "a@b.com"}, "list": ["x@y.com"], "plain": "user@test.com"}
        result = ContextHygiene.sanitize(args)
        assert "a@b.com" not in result["nested"]["email"]
        assert "x@y.com" not in result["list"][0]
        assert "user@test.com" not in result["plain"]



class TestSemanticGate:
    def setup_method(self):
        self.gate = SemanticGate({"auto_approve": True})

    def test_no_api_key_skips_gate(self):
        allowed, reason = self.gate.check_action("test action")
        assert allowed
        assert "no api key" in reason.lower()

