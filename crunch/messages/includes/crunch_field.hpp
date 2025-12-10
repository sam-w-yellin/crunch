#pragma once

#include <algorithm>
#include <array>
#include <concepts>
#include <crunch_scalar.hpp>
#include <crunch_string.hpp>
#include <crunch_types.hpp>
#include <crunch_validators.hpp>
#include <cstdint>
#include <optional>
#include <span>

namespace Crunch::serdes {
template <std::size_t Alignment>
struct StaticLayout;
struct TlvLayout;
}  // namespace Crunch::serdes

namespace Crunch::messages {

// Concept to identify a message type
template <typename T>
concept IsMessage = requires {
    { T::message_id };
};

/**
 * @brief Concept for a Presence Validator.
 */
template <typename T>
concept IsPresenceValidator = requires(bool set, FieldId id) {
    { T::check_presence(set, id) } -> std::same_as<std::optional<Error>>;
};

/**
 * @brief Wrapper for a message field within a CrunchMessage.
 *
 * Associates a FieldId and Presence requirements with a data Type.
 *
 * @tparam Id The unique FieldId.
 * @tparam PresenceValidator The presence validation policy (Optional/Required).
 * @tparam Type The underlying field type (Scalar, String, Array, or Message).
 */
template <FieldId Id, typename PresenceValidator, typename Type>
    requires IsPresenceValidator<PresenceValidator>
class Field {
   public:
    static constexpr FieldId field_id = Id;
    using FieldType = Type;

    constexpr Field() noexcept = default;

    /**
     * @brief Check presence requirement.
     * @return std::optional<Error> Error if presence check fails, otherwise
     * std::nullopt.
     */
    [[nodiscard]] constexpr auto validate_presence() const noexcept
        -> std::optional<Error> {
        return PresenceValidator::check_presence(set_, Id);
    }

    /**
     * @brief Set the value.
     *
     * @return - std::optional<Error> for types that validate on set (String,
     * Array).
     * @return - void for types that cannot fail on set (Scalar, Message).
     */
    template <typename T>
    [[nodiscard]] constexpr auto set(const T& val) noexcept {
        if constexpr (requires {
                          {
                              value_.set(val)
                          } -> std::same_as<std::optional<Error>>;
                      }) {
            auto err = value_.set(val);
            if (!err) {
                set_ = true;
            }
            return err;
        } else if constexpr (requires { value_.set(val); }) {
            value_.set(val);
            set_ = true;
        } else {
            // Submessages do not have set(), so we assign.
            value_ = val;
            set_ = true;
        }
    }

    /**
     * @brief Set the value, bypassing validation
     */
    template <typename T>
    constexpr void set_without_validation(const T& val) noexcept
        requires(!fields::is_string_v<Type> && !IsMessage<Type>)
    {
        value_.set_without_validation(val);
        set_ = true;
    }

    /**
     * @brief Get the user-facing value.
     *
     * @return - Messages: const T* (nullptr if unset).
     * @return - Scalars/Strings: std::optional<ValueType> (nullopt if unset).
     * @return - Arrays: std::optional<std::span<const ValueType>> (nullopt if
     * unset).
     */

    [[nodiscard]] constexpr auto get() const noexcept {
        if constexpr (IsMessage<Type>) {
            return get_message_impl();
        } else if constexpr (fields::is_scalar_v<Type>) {
            return get_scalar_impl();
        } else if constexpr (fields::is_string_v<Type>) {
            return get_string_impl();
        } else {
            return std::nullopt;
        }
    }

    /**
     * @brief Clear the field value.
     */
    constexpr void clear() noexcept {
        set_ = false;
        value_ = {};
    }

    /**
     * @brief Validate the field value.
     * @return std::optional<Error> Error if validation fails, otherwise
     * std::nullopt.
     */
    [[nodiscard]] constexpr auto Validate() const noexcept
        -> std::optional<Error> {
        if (!set_) {
            return std::nullopt;
        }
        return value_.Validate();
    }

    [[nodiscard]] constexpr bool operator==(const Field& other) const noexcept {
        if (set_ != other.set_) {
            return false;
        }
        if (!set_) {
            return true;
        }
        return value_ == other.value_;
    }

   private:
    [[nodiscard]] constexpr auto get_message_impl() const noexcept {
        return set_ ? &value_ : nullptr;
    }

    [[nodiscard]] constexpr auto get_scalar_impl() const noexcept {
        using V = typename Type::ValueType;
        auto ret = std::optional<V>{};
        if (set_) {
            ret.emplace(value_.get());
        }
        return ret;
    }

    [[nodiscard]] constexpr auto get_string_impl() const noexcept {
        auto ret = std::optional<std::string_view>{};
        if (set_) {
            ret.emplace(value_.get());
        }
        return ret;
    }

    [[nodiscard]] constexpr auto get_array_impl() const noexcept {
        using V = typename Type::ValueType;
        using SpanT = std::span<const V>;
        auto ret = std::optional<SpanT>{};
        if (set_) {
            ret.emplace(SpanT{value_.begin(), value_.end()});
        }
        return ret;
    }

    Type value_{};
    bool set_{false};

    /**
     * @brief The serdes layout needs access to the internal state for efficent
     *        deserialization.
     * TODO: Figure out a way to manage this without friends and give plugin
     *       serializers access to the internal state without adding each new
     *       serializer to the Field class. Maybe via a proxy class.
     */
    template <std::size_t Alignment>
    friend struct Crunch::serdes::StaticLayout;
    friend struct Crunch::serdes::TlvLayout;
};

template <typename T>
struct is_field : std::false_type {};

template <FieldId Id, typename P, typename T>
struct is_field<Field<Id, P, T>> : std::true_type {};

template <typename T>
inline constexpr bool is_field_v = is_field<T>::value;

/**
 * @brief Concept to detect if a type has a Validate(FieldId) method.
 */
template <typename T>
concept HasValidateWithId = requires(const T& t, FieldId id) {
    { t.Validate(id) } -> std::same_as<std::optional<Error>>;
};

/**
 * @brief Concept to detect if a type has a parameterless Validate() method.
 */
template <typename T>
concept HasValidateNoId = requires(const T& t) {
    { t.Validate() } -> std::same_as<std::optional<Error>>;
};

/**
 * @brief Concept to detect if a type quacks like a Crunch Message.
 */
template <typename T>
concept HasCrunchMessageInterface = requires {
    { std::integral_constant<MessageId, T::message_id>{} };
    { T{}.get_fields() };
};

/**
 * @brief Concept for valid element types within Field or ArrayField.
 * Must be a scalar, string, or message.
 */
template <typename T>
concept ValidElementType = fields::is_scalar_v<std::remove_cvref_t<T>> ||
                           fields::is_string_v<std::remove_cvref_t<T>> ||
                           HasCrunchMessageInterface<std::remove_cvref_t<T>>;

/**
 * @brief Self-contained array field with storage, validation, and field
 * metadata.
 *
 * Arrays do not have Required/Optional presence - "set" is derived from size()
 * > 0. Use array-level validators like LengthAtLeast<N> instead.
 *
 * @tparam Id The unique FieldId.
 * @tparam ElementType The element type (Scalar, String, or Message).
 * @tparam MaxSize Maximum number of elements.
 * @tparam Validators Validators to apply to the Array (e.g., LengthAtLeast).
 */
template <FieldId Id, typename ElementType, std::size_t MaxSize,
          typename... Validators>
    requires(ValidElementType<ElementType> && (sizeof...(Validators) >= 1))
class ArrayField {
   public:
    static constexpr FieldId field_id = Id;
    static constexpr std::size_t max_size = MaxSize;
    using ValueType = ElementType;
    // FieldType is self-referential for serialization compatibility
    using FieldType = ArrayField;

    constexpr ArrayField() noexcept = default;

    /**
     * @brief Arrays don't have presence validation - always returns nullopt.
     * Use array validators (LengthAtLeast, etc.) instead.
     * @return Always std::nullopt.
     */
    [[nodiscard]] constexpr auto validate_presence() const noexcept
        -> std::optional<Error> {
        return std::nullopt;
    }

    /**
     * @brief Adds an element to the array.
     * @param val The value to add.
     * @return std::nullopt on success, or CapacityExceeded error.
     */
    constexpr std::optional<Error> add(const ElementType& val) noexcept {
        if (current_len_ >= MaxSize) {
            return Error::capacity_exceeded(Id, "array capacity exceeded");
        }
        items_[current_len_++] = val;
        return std::nullopt;
    }

    /**
     * @brief Set array contents from a std::array.
     * @tparam N Size of the input array. Must be <= MaxSize.
     * @return std::nullopt on success.
     */
    template <std::size_t N>
        requires(N <= MaxSize)
    constexpr std::optional<Error> set(
        const std::array<ElementType, N>& other) noexcept {
        current_len_ = N;
        std::copy(other.begin(), other.end(), items_.begin());
        return std::nullopt;
    }

    /**
     * @brief Set array contents from another ArrayField.
     * @return std::nullopt on success.
     */
    constexpr std::optional<Error> set(const ArrayField& other) noexcept {
        *this = other;
        return std::nullopt;
    }

    /**
     * @brief Clear the array (sets size to 0).
     */
    constexpr void clear() noexcept { current_len_ = 0; }

    /**
     * @brief Get the current number of elements.
     * @return Number of elements in the array.
     */
    [[nodiscard]] constexpr std::size_t size() const noexcept {
        return current_len_;
    }

    /**
     * @brief Check if the array is empty.
     * @return true if size() == 0, false otherwise.
     */
    [[nodiscard]] constexpr bool empty() const noexcept {
        return current_len_ == 0;
    }

    /**
     * @brief Get read-only span of active elements.
     * @return std::span<const ElementType> of current elements.
     */
    [[nodiscard]] constexpr auto get() const noexcept {
        using SpanT = std::span<const ElementType>;
        return SpanT{items_.data(), current_len_};
    }

    /**
     * @brief Access element at index (unchecked).
     * @return Const reference to element.
     */
    constexpr const ElementType& operator[](std::size_t index) const noexcept {
        return items_[index];
    }

    /**
     * @brief Access element at index.
     * @return Const reference to element.
     */
    constexpr const ElementType& at(std::size_t index) const {
        return items_[index];
    }

    /**
     * @brief Validates the array and its elements.
     * @return std::nullopt on success, or Error on validation failure.
     */
    [[nodiscard]] constexpr auto Validate() const noexcept
        -> std::optional<Error> {
        // Validate each element
        for (std::size_t i = 0; i < current_len_; ++i) {
            std::optional<Error> err;
            if constexpr (HasValidateWithId<ElementType>) {
                err = items_[i].Validate(Id);
            } else if constexpr (HasValidateNoId<ElementType>) {
                err = items_[i].Validate();
            }
            if (err.has_value()) {
                return err;
            }
        }

        // Run array-level validators
        if constexpr (sizeof...(Validators) > 0) {
            for (const auto& result : {Validators::Check(*this, Id)...}) {
                if (result.has_value()) {
                    return result;
                }
            }
        }

        return std::nullopt;
    }

    [[nodiscard]] constexpr bool operator==(
        const ArrayField& other) const noexcept {
        if (current_len_ != other.current_len_) {
            return false;
        }
        return std::equal(items_.begin(), items_.begin() + current_len_,
                          other.items_.begin());
    }

    // STL iterator support
    auto begin() const noexcept { return items_.begin(); }
    auto end() const noexcept { return items_.begin() + current_len_; }
    auto begin() noexcept { return items_.begin(); }
    auto end() noexcept { return items_.begin() + current_len_; }

   private:
    std::array<ElementType, MaxSize> items_{};
    std::size_t current_len_{0};

    template <std::size_t Alignment>
    friend struct Crunch::serdes::StaticLayout;
    friend struct Crunch::serdes::TlvLayout;
};

template <typename T>
struct is_array_field : std::false_type {};

template <FieldId Id, typename E, std::size_t M, typename... V>
struct is_array_field<ArrayField<Id, E, M, V...>> : std::true_type {};

template <typename T>
inline constexpr bool is_array_field_v = is_array_field<T>::value;

}  // namespace Crunch::messages
