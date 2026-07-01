import re
from pathlib import Path


def test_no_env_file_committed():
    env_path = Path(__file__).parent.parent / ".env"
    assert not env_path.exists(), ".env must not be committed"


def test_env_example_is_placeholder():
    example = Path(__file__).parent.parent / "sdg" / ".env.example"
    content = example.read_text()
    assert "OPENROUTER_API_KEY=your_key_here" in content
    assert not re.search(r"sk-or-v1-[a-f0-9]{32,}", content)
