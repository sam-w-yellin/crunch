load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

cc_library(
    name = "integrity",
    hdrs = ["includes/crunch_integrity.hpp"],
    includes = ["includes"],
    strip_include_prefix = "includes",
    visibility = ["//visibility:public"],
)

cc_test(
    name = "test-integrity",
    srcs = ["test/test_integrity.cpp"],
    deps = [
        ":integrity",
        "//crunch/test_utils:test_main",
        "@catch2//:catch2",
    ],
)
