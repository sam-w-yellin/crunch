load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

cc_library(
    name = "scalar",
    hdrs = ["includes/crunch_scalar.hpp"],
    includes = ["includes"],
    strip_include_prefix = "includes",
    visibility = ["//visibility:public"],
    deps = [
        "//crunch/core:core",
        "//crunch/validators:validators",
    ],
)

cc_library(
    name = "enum",
    hdrs = ["includes/crunch_enum.hpp"],
    includes = ["includes"],
    strip_include_prefix = "includes",
    visibility = ["//visibility:public"],
    deps = [
        ":scalar",
        "//crunch/validators:validators",
    ],
)

cc_library(
    name = "string",
    hdrs = ["includes/crunch_string.hpp"],
    includes = ["includes"],
    strip_include_prefix = "includes",
    visibility = ["//visibility:public"],
    deps = [
        "//crunch/core:core",
        "//crunch/validators:validators",
    ],
)


cc_test(
    name = "test-scalar",
    srcs = [
        "test/test_scalars.cpp", 
    ],
    deps = [
        "@catch2//:catch2",
        ":scalar",
        "//crunch/test_utils:test_main",
    ]
)

cc_test(
    name = "test-string",
    srcs = ["test/test_string.cpp"],
    deps = [
        ":string",
        "//crunch/test_utils:test_main",
        "//crunch/validators:validators",
        "@catch2//:catch2",
    ],
)

cc_test(
    name = "test-arrays",
    srcs = ["test/test_arrays.cpp"],
    deps = [
        ":scalar",
        "//crunch/messages:messages",
        "//crunch/test_utils:test_main",
        "@catch2//:catch2",
    ],
)