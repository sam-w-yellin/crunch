load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "tlv_layout_test",
    srcs = ["test_tlv_layout.cpp"],
    deps = [
        "//include:crunch",
        "@catch2//:catch2_main",
    ],
)

cc_test(
    name = "varint_test",
    srcs = ["test_varint.cpp"],
    deps = [
        "//include:crunch",
        "@catch2//:catch2_main",
    ],
)
