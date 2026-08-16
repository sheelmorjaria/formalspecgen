import pytest

from pipeline.java_inspection import DETECTOR_REGISTRY, inspect_java_file
from pipeline.pattern_registry import PATTERN_REGISTRY, PatternPlugin
from pipeline.pattern_registry import DETECTOR_REGISTRY as REGISTRY_DETECTORS

APPLY_REFACTOR_SLUGS = {"extract-method", "factory-method", "state",
                        "decorator", "facade", "null-object"}
ALLOWED_CATEGORIES = {"Creational", "Structural", "Behavioral", "Concurrency"}
NEW_CODES = {"guard-delegation", "string-command-dispatch", "bounded-buffer"}


def _inspect(tmp_path, source):
    path = tmp_path / "Example.java"
    path.write_text(source, encoding="utf-8")
    return inspect_java_file(path)


PROXY_POSITIVE = '''public class Example implements Service {
    private final Service real;
    public Example(Service real) { this.real = real; }
    public int read(int key) { if (key < 0) { return -1; } return real.read(key); }
    public void write(int key) { if (key >= 0) { real.write(key); } }
}'''

PROXY_NEAR_MISS = '''public class Example implements Service {
    private final Service real;
    public Example(Service real) { this.real = real; }
    public int read(int key) { return real.read(key); }
    public void write(int key) { real.write(key); }
}'''

COMMAND_SWITCH_POSITIVE = '''public class Example {
    public void run(String command) {
        switch (command) {
            case "start": engine.start(); break;
            case "stop": engine.stop(); break;
            case "reset": engine.reset(); break;
            default: break;
        }
    }
}'''

COMMAND_IF_POSITIVE = '''public class Example {
    public void run(String command) {
        if (command.equals("start")) { engine.start(); }
        else if (command == "stop") { engine.stop(); }
        else if ("reset".equals(command)) { engine.reset(); }
    }
}'''

COMMAND_NEAR_MISS = '''public class Example {
    public void run(String command) {
        if (command.equals("start")) { engine.start(); }
        else if (command.equals("stop")) { engine.stop(); }
    }
}'''

PRODUCER_CONSUMER_POSITIVE = '''public class Example {
    private int[] buffer;
    private int count;
    public void put(int value) { buffer[count] = value; count = count + 1; }
    public int get() { count = count - 1; return buffer[count]; }
}'''

PRODUCER_CONSUMER_MONITOR_POSITIVE = '''public class Example {
    private Object[] slots;
    public void put(Object value) { notifyAll(); }
    public Object take() { wait(); return null; }
}'''

PRODUCER_CONSUMER_NEAR_MISS = '''public class Example {
    private int[] buffer;
    public int get() { return buffer[0]; }
}'''

FIXTURE_TABLE = [
    (PROXY_POSITIVE, "guard-delegation"),
    (PROXY_NEAR_MISS, None),
    (COMMAND_SWITCH_POSITIVE, "string-command-dispatch"),
    (COMMAND_IF_POSITIVE, "string-command-dispatch"),
    (COMMAND_NEAR_MISS, None),
    (PRODUCER_CONSUMER_POSITIVE, "bounded-buffer"),
    (PRODUCER_CONSUMER_MONITOR_POSITIVE, "bounded-buffer"),
    (PRODUCER_CONSUMER_NEAR_MISS, None),
]


@pytest.mark.parametrize("source,expected_code", FIXTURE_TABLE)
def test_new_detector_fixture_expectations(tmp_path, source, expected_code):
    result = _inspect(tmp_path, source)
    codes = {finding["code"] for finding in result["findings"]}
    if expected_code is None:
        assert not (NEW_CODES & codes)
    else:
        assert expected_code in codes


def test_new_finding_metadata_and_recommendations(tmp_path):
    proxy = next(finding for finding in _inspect(tmp_path, PROXY_POSITIVE)["findings"]
                 if finding["code"] == "guard-delegation")
    assert proxy["severity"] == "info"
    assert proxy["suggested_pattern"] == "Proxy"
    assert proxy["methods"] == ["read", "write"]
    assert proxy["wrapped_fields"] == ["real"]

    command = next(finding for finding in
                   _inspect(tmp_path, COMMAND_SWITCH_POSITIVE)["findings"]
                   if finding["code"] == "string-command-dispatch")
    assert command["severity"] == "warning"
    assert command["suggested_pattern"] == "Command"
    assert command["method"] == "run"

    producer = next(finding for finding in
                    _inspect(tmp_path, PRODUCER_CONSUMER_POSITIVE)["findings"]
                    if finding["code"] == "bounded-buffer")
    assert producer["severity"] == "info"
    assert producer["suggested_pattern"] == "Producer-Consumer"
    assert producer["put_methods"] == ["put"]
    assert producer["get_methods"] == ["get"]
    assert "TLC" in producer["recommendation"]
    assert "overflow/underflow" in producer["recommendation"]


def test_registry_names_are_unique():
    names = [plugin.name for plugin in PATTERN_REGISTRY]
    assert len(names) == len(set(names))
    assert all(isinstance(plugin, PatternPlugin) for plugin in PATTERN_REGISTRY)


def test_registry_categories_are_within_the_catalog():
    assert {plugin.category for plugin in PATTERN_REGISTRY} == ALLOWED_CATEGORIES
    assert all("java" in plugin.languages for plugin in PATTERN_REGISTRY)


def test_registry_action_profiles_are_refactor_slugs():
    for plugin in PATTERN_REGISTRY:
        assert plugin.action_profile in APPLY_REFACTOR_SLUGS | {None}
    profiles = {plugin.name: plugin.action_profile for plugin in PATTERN_REGISTRY}
    assert profiles["Factory Method"] == "factory-method"
    assert profiles["State"] == "state"
    assert profiles["Decorator"] == "decorator"
    assert profiles["Null Object"] == "null-object"
    assert profiles["Proxy"] is None
    assert profiles["Command"] is None
    assert profiles["Producer-Consumer"] is None


def test_detector_registry_covers_every_registered_plugin():
    assert len(PATTERN_REGISTRY) == 13
    assert len(DETECTOR_REGISTRY) == 13
    assert len(REGISTRY_DETECTORS) == 13
    assert DETECTOR_REGISTRY == REGISTRY_DETECTORS == tuple(
        plugin.detector for plugin in PATTERN_REGISTRY)
