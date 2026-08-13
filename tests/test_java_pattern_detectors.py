from pipeline.java_inspection import DETECTOR_REGISTRY, PatternDetector, inspect_java_file


def _inspect(tmp_path, source):
    path = tmp_path / "Example.java"
    path.write_text(source, encoding="utf-8")
    return inspect_java_file(path)


def test_detector_registry_is_explicit_and_base_is_abstract_by_contract():
    assert len(DETECTOR_REGISTRY) == 6
    try:
        PatternDetector("", None).detect()
    except NotImplementedError:
        pass
    else:
        raise AssertionError("base detector accepted analysis")


def test_singleton_shape_recommends_dependency_injection(tmp_path):
    result = _inspect(tmp_path, '''public class Example {
        private Example() {}
        public static Example getInstance() { return new Example(); }
    }''')
    finding = result["findings"][0]
    assert finding["code"] == "singleton-global-access"
    assert finding["suggested_pattern"] == "Dependency Injection"


def test_observer_registry_builder_and_repository_opportunities(tmp_path):
    observer = _inspect(tmp_path, '''import java.util.List;
    public class Example {
        private List<EventListener> listeners;
        public void addEventListener(EventListener value) {}
        public void removeEventListener(EventListener value) {}
    }''')
    assert observer["findings"][0]["code"] == "listener-registry"

    builder = _inspect(tmp_path, '''public class Example {
        public Object make() { return new User("a", "b", 1, true, "c", 2); }
    }''')
    assert builder["findings"][0]["suggested_pattern"] == "Builder"

    repository = _inspect(tmp_path, '''public class Example {
        private Connection connection;
        public int save(int amount) {
            connection.executeQuery();
            if (amount > 0) { return amount + 1; }
            return 0;
        }
    }''')
    assert repository["findings"][0]["code"] == "mixed-persistence-logic"


def test_delegation_wrapper_recommends_adapter(tmp_path):
    result = _inspect(tmp_path, '''public class Example {
        private final Vendor vendor;
        public Example(Vendor vendor) { this.vendor = vendor; }
        public int convert(int value) { return vendor.convert(value); }
        public void reset() { vendor.reset(); }
    }''')
    finding = result["findings"][0]
    assert finding["code"] == "delegation-wrapper"
    assert finding["suggested_pattern"] == "Adapter"


def test_near_misses_do_not_trigger_catalog_recommendations(tmp_path):
    result = _inspect(tmp_path, '''public class Example {
        private final Vendor first;
        private final Vendor second;
        public Example(Vendor first) { this.first = first; this.second = first; }
        public void one() { first.run(); }
        public void two() { int local = 1; first.run(); }
        public static String getInstance() { return "not self typed"; }
        public Object make(int value) { return new User(value, value, value, value, value, value); }
        public void save() { connection.executeQuery(); }
    }''')
    catalog = {"singleton-global-access", "listener-registry", "large-literal-construction",
               "mixed-persistence-logic", "delegation-wrapper"}
    assert not (catalog & {finding["code"] for finding in result["findings"]})


def test_adapter_near_miss_thresholds_and_unqualified_assignment(tmp_path):
    too_few = _inspect(tmp_path, '''public class Example {
        private Vendor vendor;
        public Example(Vendor input) { vendor = input; }
        public void one() { vendor.run(); }
    }''')
    assert not any(item["code"] == "delegation-wrapper" for item in too_few["findings"])

    low_ratio = _inspect(tmp_path, '''public class Example {
        private Vendor vendor;
        public Example(Vendor input) { vendor = input; }
        public void one() { vendor.run(); }
        public void two() { int local = 1; vendor.run(); }
    }''')
    assert not any(item["code"] == "delegation-wrapper" for item in low_ratio["findings"])
