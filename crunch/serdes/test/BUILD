load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "varint-test",
    srcs = ["test_varint.cpp"],
    deps = [
        "//crunch/serdes:varint",
        "@catch2//:catch2",
        "//crunch/test_utils:test_main",
    ],
)

cc_test(
    name = "tlv_layout_test",
    srcs = ["test_tlv_layout.cpp"],
    deps = [
        "//crunch/api:api",
        "//crunch/serdes:serdes",
        "//crunch/messages:messages",
        "//crunch/fields:string",
        "@catch2//:catch2",
        "//crunch/test_utils:test_main",
    ],
)
