load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

cc_library(
    name = "api",
    hdrs = [
        "includes/crunch.hpp",
        "includes/crunch_detail.hpp",
    ],
    includes = ["includes"],
    strip_include_prefix = "includes",
    visibility = ["//visibility:public"],
    deps = [
        "//crunch/messages:messages",
        "//crunch/integrity:integrity",
        "//crunch/serdes:serdes",
        "//crunch/fields:enum",
        "//crunch/fields:string",
    ],
)

cc_test(
    name = "e2e_test",
    srcs = ["test/test_e2e.cpp"],
    deps = [
        ":api",
        "//crunch/test_utils:test_main",
        "//crunch/fields:scalar",
        "//crunch/fields:enum",
        "//crunch/fields:string",
        "//crunch/validators:validators",
        "@catch2//:catch2",
    ],
)

cc_test(
    name = "integrity_test",
    srcs = ["test/test_integrity.cpp"],
    deps = [
        ":api",
        "//crunch/test_utils:test_main",
        "//crunch/fields:scalar",
        "//crunch/fields:enum",
        "//crunch/fields:string",
        "//crunch/validators:validators",
        "@catch2//:catch2",
    ],
)

cc_test(
    name = "validation_test",
    srcs = ["test/test_validation.cpp"],
    deps = [
        ":api",
        "//crunch/test_utils:test_main",
        "//crunch/fields:scalar",
        "//crunch/fields:enum",
        "//crunch/fields:string",
        "//crunch/validators:validators",
        "@catch2//:catch2",
    ],
)

cc_test(
    name = "types_test",
    srcs = ["test/test_types.cpp"],
    deps = [
        ":api",
        "//crunch/test_utils:test_main",
        "//crunch/fields:scalar",
        "//crunch/fields:enum",
        "//crunch/fields:string",
        "//crunch/validators:validators",
        "@catch2//:catch2",
    ],
)

cc_test(
    name = "submessages_test",
    srcs = ["test/test_submessages.cpp"],
    deps = [
        ":api",
        "//crunch/test_utils:test_main",
        "//crunch/fields:scalar",
        "//crunch/fields:enum",
        "//crunch/fields:string",
        "//crunch/validators:validators",
        "@catch2//:catch2",
    ],
)
