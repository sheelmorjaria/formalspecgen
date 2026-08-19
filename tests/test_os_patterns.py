# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""M40: OS-pattern extraction — intrusive lists and callbacks."""
from __future__ import annotations

from pipeline.os_patterns import extract_intrusive_list, resolve_callbacks

DEV_LIST = """struct list_head {
    struct list_head *next, *prev;
};

struct device {
    int id;
    struct list_head links;
};

void register_dev(struct device *d) {
    list_add(&d->links, &device_list);
}

void unregister_dev(struct device *d) {
    list_del(&d->links);
}
"""

FOPS = """ssize_t dev_read(int fd) { return 0; }
ssize_t dev_write(int fd) { return 0; }
extern ssize_t vendor_ioctl(int fd);

struct file_operations dev_fops = {
    .read = dev_read,
    .write = dev_write,
    .unlocked_ioctl = vendor_ioctl,
};

void late_bind(void) {
    fops->open = dev_read;
}
"""


def test_intrusive_list_abstracts_to_size_counter():
    verdict = extract_intrusive_list(DEV_LIST, capacity=8)
    assert verdict["status"] == "INTRUSIVE_LIST_ABSTRACTED"
    assert verdict["abstract_state_field"] == "size"
    assert verdict["list_heads"] == ["links"]
    assert {t["name"] for t in verdict["transitions"]} == \
        {"list_add", "list_del"}
    assert verdict["size_invariant"] == "0 <= size <= 8"
    assert "UNBOUNDED_HEAP_DETECTED" in verdict["abstraction"]


def test_intrusive_list_residuals_fail_closed():
    assert extract_intrusive_list("int f(void){return 0;}",
                                  4)["code"] == "no_list_head"
    head_only = "struct device { struct list_head links; };"
    assert extract_intrusive_list(head_only, 4)["code"] == \
        "no_list_operations"
    no_cap = extract_intrusive_list(DEV_LIST)
    assert no_cap["code"] == "pool_capacity_missing"
    assert "never guesses" in no_cap["message"]
    exceed = "void f(void){ list_add(a, b); list_add(c, d); }"
    assert extract_intrusive_list(
        "struct device { struct list_head links; };\n" + exceed,
        1)["code"] == "capacity_exceeded"


def test_callbacks_resolve_and_flag_unresolved():
    verdict = resolve_callbacks(FOPS)
    assert verdict["status"] == "CALLBACKS_PARTIALLY_RESOLVED"
    resolved = {r["target"] for r in verdict["registrations"]
                if r["resolves_in_source"]}
    assert resolved == {"dev_read", "dev_write"}
    assert verdict["machines_for_extraction"] == ["dev_read", "dev_write"]
    assert verdict["unresolved"] == ["vendor_ioctl"]
    assert verdict["unresolved_note"]

    clean = resolve_callbacks(
        "int a(void){return 0;}\nstruct file_operations f = "
        "{.read = a};\n")
    assert clean["status"] == "CALLBACKS_RESOLVED"
    assert clean["unresolved"] == []
    assert resolve_callbacks("int main(void){return 0;}")["code"] == \
        "no_callback_registrations"
