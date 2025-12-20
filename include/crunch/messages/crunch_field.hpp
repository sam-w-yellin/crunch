#pragma once

#include <algorithm>
#include <array>
#include <concepts>
#include <crunch/core/crunch_types.hpp>
#include <crunch/fields/crunch_scalar.hpp>
#include <crunch/fields/crunch_string.hpp>
#include <crunch/validators/crunch_validators.hpp>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

namespace Crunch::serdes {
template <std::size_t Alignment>
struct StaticLayout;
struct TlvLayout;
}  // namespace Crunch::serdes

namespace Crunch::messages {

/**
 * @brief Concept to identify a message type.
 */
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
    static_assert(Id <= MaxFieldId, "FieldId must be <= MaxFieldId (2^29 - 1)");
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
 */
template <FieldId Id, typename ElementType, std::size_t MaxSize,
          typename... Validators>
class ArrayField;

template <FieldId Id, typename KeyField, typename ValueField,
          std::size_t MaxSize, typename... Validators>
class MapField;

// Traits defined early for use in Concepts
template <typename T>
struct is_array_field : std::false_type {};

template <FieldId Id, typename E, std::size_t M, typename... V>
struct is_array_field<ArrayField<Id, E, M, V...>> : std::true_type {};

template <typename T>
inline constexpr bool is_array_field_v = is_array_field<T>::value;

template <typename T>
struct is_map_field : std::false_type {};

template <FieldId Id, typename K, typename V, std::size_t M, typename... Vs>
struct is_map_field<MapField<Id, K, V, M, Vs...>> : std::true_type {};

template <typename T>
inline constexpr bool is_map_field_v = is_map_field<T>::value;

/**
 * @brief Concept for valid element type in Array/Map.
 * Must be a scalar, string, message, array, or map.
 */
template <typename T>
concept ValidElementType =
    Crunch::fields::is_scalar_v<std::remove_cvref_t<T>> ||
    Crunch::fields::is_string_v<std::remove_cvref_t<T>> ||
    HasCrunchMessageInterface<std::remove_cvref_t<T>> ||
    is_array_field_v<std::remove_cvref_t<T>> ||
    is_map_field_v<std::remove_cvref_t<T>>;

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
class ArrayField {
    static_assert(ValidElementType<ElementType>,
                  "Invalid ElementType for ArrayField");
    static_assert(sizeof...(Validators) >= 1,
                  "ArrayField requires at least one validator");
    static_assert(Id <= MaxFieldId, "FieldId must be <= MaxFieldId (2^29 - 1)");

   public:
    static constexpr FieldId field_id = Id;
    // cppcheck-suppress unusedStructMember
    static constexpr std::size_t max_size = MaxSize;
    using ValueType = ElementType;
    using FieldType = ArrayField;

    constexpr ArrayField() noexcept = default;

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

// Helper to extract ValueType for Scalar/String, or use T itself for others
template <typename T>
struct field_value_type {
    using type = T;
};

template <typename T>
    requires Crunch::fields::is_scalar_v<T> || Crunch::fields::is_string_v<T>
struct field_value_type<T> {
    using type = typename T::ValueType;
};

template <typename T>
using field_value_type_t = typename field_value_type<T>::type;

/**
 * @brief Map field mapping keys to values.
 *
 * Backed by std::array<std::pair<KeyField, ValueField>, MaxSize>.
 * Keys and Values are other Crunch fields.
 *
 * @tparam Id The unique FieldId.
 * @tparam KeyField The type of the key field.
 * @tparam ValueField The type of the value field.
 * @tparam MaxSize Maximum number of key-value pairs.
 * @tparam Validators Validators to apply to the Map.
 */
template <FieldId Id, typename KeyField, typename ValueField,
          std::size_t MaxSize, typename... Validators>
class MapField {
    static_assert(ValidElementType<KeyField>, "Invalid KeyField type");
    static_assert(ValidElementType<ValueField>, "Invalid ValueField type");
    static_assert(Id <= MaxFieldId, "FieldId must be <= MaxFieldId (2^29 - 1)");

   public:
    static constexpr FieldId field_id = Id;
    // cppcheck-suppress unusedStructMember
    static constexpr std::size_t max_size = MaxSize;

    using KeyType = field_value_type_t<KeyField>;
    using ValueType = field_value_type_t<ValueField>;
    using PairType = std::pair<KeyField, ValueField>;
    using FieldType = MapField;

    constexpr MapField() noexcept = default;

    /**
     * @brief Inserts a key-value pair into the map.
     * @param key The key to insert.
     * @param value The value to insert.
     * @return std::nullopt on success, or Error (CapacityExceeded or
     * InvalidValue).
     */
    constexpr std::optional<Error> insert(const KeyType& key,
                                          const ValueType& value) noexcept {
        std::optional<Error> err;

        // Validate Key
        if constexpr (Crunch::fields::is_scalar_v<KeyField> ||
                      Crunch::fields::is_string_v<KeyField>) {
            // For scalar/string, KeyType is value type. Validate against
            // validator.
            err = KeyField::Validate(key, 0);
        } else {
            // For complex, KeyType is field type. Validate against internal
            // rules.
            err = key.Validate();
        }
        if (err) {
            return err;
        }

        // Validate Value
        if constexpr (Crunch::fields::is_scalar_v<ValueField> ||
                      Crunch::fields::is_string_v<ValueField>) {
            err = ValueField::Validate(value, 0);
        } else {
            err = value.Validate();
        }
        if (err) {
            return err;
        }

        if (current_len_ >= MaxSize) {
            return Error::capacity_exceeded(Id, "map capacity exceeded");
        }

        // Check for duplicate key
        if (at(key).has_value()) {
            return Error::validation(Id, "Duplicate key in map");
        }

        auto& pair = items_[current_len_];

        // 3. Store Key
        if constexpr (Crunch::fields::is_scalar_v<KeyField>) {
            pair.first.set_without_validation(key);
        } else if constexpr (Crunch::fields::is_string_v<KeyField>) {
            static_cast<void>(pair.first.set(key));
        } else {
            pair.first = key;
        }

        // 4. Store Value
        if constexpr (Crunch::fields::is_scalar_v<ValueField>) {
            pair.second.set_without_validation(value);
        } else if constexpr (Crunch::fields::is_string_v<ValueField>) {
            static_cast<void>(pair.second.set(value));
        } else {
            pair.second = value;
        }

        current_len_++;
        return std::nullopt;
    }

    // Overload for inserting std::pair
    constexpr std::optional<Error> insert(
        const std::pair<KeyType, ValueType>& p) noexcept {
        return insert(p.first, p.second);
    }

    /**
     * @brief Removes a key and its value from the map.
     * @param key The key to remove.
     * @return true if the key was found and removed, false otherwise.
     */
    // cppcheck-suppress unusedFunction
    constexpr bool remove(const KeyType& key) noexcept {
        for (std::size_t i = 0; i < current_len_; ++i) {
            const auto& stored_key_field = items_[i].first;
            if (key_equals(stored_key_field, key)) {
                // Found key at index i.
                // Clear element at i
                items_[i].first.clear();
                items_[i].second.clear();

                // Shift remaining elements down
                for (std::size_t j = i; j < current_len_ - 1; ++j) {
                    items_[j] = items_[j + 1];
                }
                // Clear last element (now duplicated at penultimate pos)
                // Actually the move assignment above likely did a copy.
                // We should clear the old last element slot to be safe/clean.
                items_[current_len_ - 1].first.clear();
                items_[current_len_ - 1].second.clear();

                current_len_--;
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Get reference to value by key.
     * @param key The key to look up.
     * @return Optional pointer to the ValueField (empty if not found).
     */
    constexpr std::optional<ValueField*> at(const KeyType& key) noexcept {
        for (std::size_t i = 0; i < current_len_; ++i) {
            // We need to extract the underlying value from the KeyField to
            // compare
            const auto& stored_key_field = items_[i].first;
            // Assuming scalar/string keys have .get() returning optional or
            // value
            if (key_equals(stored_key_field, key)) {
                return &items_[i].second;
            }
        }
        return std::nullopt;
    }

    /**
     * @brief Get the current number of elements.
     */
    [[nodiscard]] constexpr std::size_t size() const noexcept {
        return current_len_;
    }

    /**
     * @brief Check if the map is empty.
     */
    [[nodiscard]] constexpr bool empty() const noexcept {
        return current_len_ == 0;
    }

    /**
     * @brief Clear the map.
     */
    constexpr void clear() noexcept { current_len_ = 0; }

    /**
     * @brief Validate the map and its elements.
     */
    [[nodiscard]] constexpr auto Validate() const noexcept
        -> std::optional<Error> {
        // Validate each pair
        for (std::size_t i = 0; i < current_len_; ++i) {
            if (const auto err = items_[i].first.Validate(); err) {
                return err;
            }
            if (const auto err = items_[i].second.Validate(); err) {
                return err;
            }
        }

        // Run map-level validators
        for (const auto& result : {Validators::Check(*this, Id)...}) {
            if (result.has_value()) {
                return result;
            }
        }

        return std::nullopt;
    }

    /**
     * @brief Checks if two maps are equal (set equality).
     * @warning This operation is O(N^2) as it performs a linear scan for each
     * element.
     */
    [[nodiscard]] constexpr bool operator==(
        const MapField& other) const noexcept {
        if (current_len_ != other.current_len_) {
            return false;
        }

        // I don't have a faster way to do this given
        // the requirement that order doesn't matter.
        // TODO: Enforce ordering? Figure out a comparison
        // operator for Arrays/Maps/Strings?
        for (std::size_t i = 0; i < current_len_; ++i) {
            const auto& my_key = items_[i].first;
            const auto& my_val = items_[i].second;

            if (!other.has_entry(my_key, my_val)) {
                return false;
            }
        }
        return true;
    }

    auto begin() const noexcept { return items_.begin(); }
    auto end() const noexcept { return items_.begin() + current_len_; }
    auto begin() noexcept { return items_.begin(); }
    auto end() noexcept { return items_.begin() + current_len_; }

   private:
    std::array<PairType, MaxSize> items_{};
    std::size_t current_len_{0};

    constexpr bool has_entry(const KeyField& key, const ValueField& val) const {
        auto it = std::find_if(
            begin(), end(), [&](const PairType& p) { return p.first == key; });
        return it != end() && it->second == val;
    }

    static constexpr bool key_equals(const KeyField& stored,
                                     const KeyType& key) {
        if constexpr (Crunch::fields::is_scalar_v<KeyField> ||
                      Crunch::fields::is_string_v<KeyField>) {
            return stored.get() == key;
        } else {
            return stored == key;
        }
    }

    template <std::size_t Alignment>
    friend struct Crunch::serdes::StaticLayout;
    friend struct Crunch::serdes::TlvLayout;
};

}  // namespace Crunch::messages
