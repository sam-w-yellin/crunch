load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

cc_library(
    name = "validators",
    hdrs = ["includes/crunch_validators.hpp"],
    includes = ["includes"],
    strip_include_prefix = "includes",
    visibility = ["//visibility:public"],
    deps = ["//crunch/core:core"]
)

cc_test(
    name = "test-validators",
    srcs = [
        "test/test_validators.cpp", 
    ],
    deps = [
        "@catch2//:catch2",
        ":validators",
        "//crunch/test_utils:test_main",
    ],
)
