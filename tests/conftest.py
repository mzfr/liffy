import pytest

@pytest.fixture
def args():
    class Args:
        def __init__(self):
            self.url = "http://test.com/index.php?page="
            self.nostager = False
            self.cookies = None
            self.relative = False
            self.location = None

    return Args()