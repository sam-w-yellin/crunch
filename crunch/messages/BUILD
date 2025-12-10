load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

cc_library(
    name = "messages",
    hdrs = ["includes/crunch_messages.hpp", "includes/crunch_field.hpp"], 
    includes = ["includes"],
    strip_include_prefix = "includes",
    visibility = ["//visibility:public"],
    deps = [
        "//crunch/core:core",
        "//crunch/fields:scalar",
        "//crunch/fields:string",
        "//crunch/validators:validators",
    ],
)


