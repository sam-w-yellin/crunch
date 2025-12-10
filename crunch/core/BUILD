load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "core",
    hdrs = ["includes/crunch_types.hpp", "includes/crunch_endian.hpp"],
    includes = ["includes"],
    strip_include_prefix = "includes",
    visibility = ["//visibility:public"],
)

cc_test(
    name = "test-endian",
    srcs = ["test/test_endian.cpp"],
    deps = [
        ":core",
        "//crunch/test_utils:test_main",
        "@catch2//:catch2",
    ],
)
