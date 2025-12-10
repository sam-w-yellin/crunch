#pragma once

#include <crunch_scalar.hpp>
#include <crunch_validators.hpp>
#include <type_traits>

namespace Crunch::fields {

/**
 * @brief Field type for strongly-typed enums (backed by int32_t).
 *
 * Enforces that E is an enum class with int32_t underlying type.
 * Note: Use validators like OneOf, EqualTo, NotEqualTo to enforce value
 * range.
 */
template <typename E, typename... Validators>
    requires std::is_enum_v<E> &&
                 std::is_same_v<std::underlying_type_t<E>, int32_t>
using Enum = Scalar<E, Validators...>;

}  // namespace Crunch::fields
