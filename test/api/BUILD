load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "e2e_test",
    srcs = ["test_e2e.cpp"],
    deps = [
        "//include:crunch",
        "@catch2//:catch2_main",
    ],
)

cc_test(
    name = "integrity_test",
    srcs = ["test_integrity.cpp"],
    deps = [
        "//include:crunch",
        "@catch2//:catch2_main",
    ],
)

cc_test(
    name = "submessages_test",
    srcs = ["test_submessages.cpp"],
    deps = [
        "//include:crunch",
        "@catch2//:catch2_main",
    ],
)

cc_test(
    name = "types_test",
    size = "small",
    srcs = ["test_types.cpp"],
    deps = [
        "//include:crunch",
        "@catch2//:catch2_main",
    ],
)

cc_test(
    name = "validation_test",
    srcs = ["test_validation.cpp"],
    deps = [
        "//include:crunch",
        "@catch2//:catch2_main",
    ],
)

cc_test(
    name = "decoder_test",
    srcs = ["test_decoder.cpp"],
    deps = [
        "//include:crunch",
        "@catch2//:catch2_main",
    ],
)
