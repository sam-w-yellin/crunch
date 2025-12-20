#pragma once

#include <array>
#include <crunch/validators/crunch_validators.hpp>
#include <cstdint>
#include <optional>

namespace Crunch::fields {

/**
 * @brief A validated, typed message field.
 *
 * Wraps a primitive, fixed-size type with validation and presence logic.
 *
 * @tparam ScalarType The underlying primitive type (e.g., int32_t). Must
 *         satisfy `std::regular`.
 * @tparam Validators One or more validators to enforce value constraints.
 *         Each must satisfy `Validator<V, ScalarType>`. At least one
 *         validator is required (use `None` for no validation).
 */
template <class ScalarType, typename... Validators>
    requires(Validator<Validators, ScalarType> && ...) &&
            (sizeof...(Validators) > 0) && std::regular<ScalarType>
class Scalar {
   public:
    using ValueType = ScalarType;

    constexpr Scalar() = default;
    // cppcheck-suppress noExplicitConstructor
    // TODO: Fixing this is a decent sized refactor
    //       and frankly its probably always fine to implicit convert.
    //       But I should come back to this and fix it at some point.
    constexpr Scalar(ScalarType v) : value_(v) {}

    constexpr std::optional<Error> set(ScalarType v) noexcept {
        if (auto err = Validate(v); err) {
            return err;
        }
        value_ = v;
        return std::nullopt;
    }

    constexpr void set_without_validation(ScalarType v) noexcept { value_ = v; }

    [[nodiscard]] constexpr ScalarType get() const noexcept { return value_; }

    constexpr void clear() noexcept { value_ = {}; }

    /**
     * @brief Checks if two fields are equal.
     */
    [[nodiscard]] constexpr bool operator==(
        const Scalar& other) const noexcept {
        return value_ == other.value_;
    }

    /**
     * @brief Validates the current value of the field against all validators.
     *
     * @return std::nullopt on success, or a validation Error.
     */
    [[nodiscard]] constexpr auto Validate() const noexcept
        -> std::optional<Error> {
        return Validate(value_);
    }

    /**
     * @brief Validates a value against all validators without setting it.
     *
     * @param v  The value to validate.
     * @param id The FieldId for this field within its message. Unused for
     *           aggregate fields.
     * @return std::nullopt on success, or a validation Error.
     */
    [[nodiscard]] static constexpr auto Validate(ScalarType v,
                                                 FieldId id = 0) noexcept
        -> std::optional<Error> {
        for (const auto& result : {Validators::Check(v, id)...}) {
            if (result.has_value()) {
                return result;
            }
        }
        return std::nullopt;
    }

   private:
    ScalarType value_{};
};

template <typename T>
struct is_scalar : std::false_type {};

template <class ScalarType, typename... Validators>
struct is_scalar<Scalar<ScalarType, Validators...>> : std::true_type {};

template <typename T>
inline constexpr bool is_scalar_v = is_scalar<T>::value;

template <typename... Validators>
using Int32 = Scalar<int32_t, Validators...>;

template <typename... Validators>
using Int16 = Scalar<int16_t, Validators...>;

template <typename... Validators>
using Int8 = Scalar<int8_t, Validators...>;

template <typename... Validators>
using UInt32 = Scalar<uint32_t, Validators...>;

template <typename... Validators>
using UInt16 = Scalar<uint16_t, Validators...>;

template <typename... Validators>
using UInt8 = Scalar<uint8_t, Validators...>;

template <typename... Validators>
using Float32 = Scalar<float, Validators...>;

template <typename... Validators>
using Float64 = Scalar<double, Validators...>;

template <typename... Validators>
using Bool = Scalar<bool, Validators...>;

}  // namespace Crunch::fields