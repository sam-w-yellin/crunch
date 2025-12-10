load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "serdes",
    hdrs = [
        "includes/crunch_static_layout.hpp",
        "includes/crunch_serdes.hpp",
        "includes/crunch_tlv_layout.hpp",
    ],
    includes = ["includes"],
    strip_include_prefix = "includes",
    visibility = ["//visibility:public"],
    deps = [
        "//crunch/core:core",
        "//crunch/messages:messages",
        "//crunch/fields:string",
        ":varint",
    ],
)

cc_library(
    name = "varint",
    hdrs = ["includes/crunch_varint.hpp"],
    includes = ["includes"],
    strip_include_prefix = "includes",
    visibility = ["//visibility:public"],
)
