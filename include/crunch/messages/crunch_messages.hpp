#pragma once

#include <concepts>
#include <crunch/core/crunch_types.hpp>
#include <crunch/fields/crunch_scalar.hpp>
#include <crunch/fields/crunch_string.hpp>
#include <crunch/messages/crunch_field.hpp>
#include <tuple>
#include <type_traits>
#include <utility>

namespace Crunch::messages {

using Crunch::Error;
using Crunch::FieldId;
using Crunch::MessageId;

/**
 * @brief Macro to define field accessors for a message.
 *
 * Generates `get_fields()` methods (const and non-const) returning a tuple
 * of references to the listed field members.
 *
 * @param ... The field member variables to include.
 */
#define CRUNCH_MESSAGE_FIELDS(...)                                      \
    constexpr auto get_fields() const { return std::tie(__VA_ARGS__); } \
    constexpr auto get_fields() { return std::tie(__VA_ARGS__); }

/**
 * @brief Concept checking if a type T has the required interface for a Crunch
 * message.
 *
 * Used internally to break dependency cycles in validation. The cycle comes
 * from messages containing fields of other messages.
 *
 * All messages must fulfill the full CrunchMessage concept, so top level users
 * are not at risk of implementing invalid messages.
 */
// Reuse concepts from crunch_field.hpp
using messages::HasCrunchMessageInterface;
using messages::ValidElementType;

/**
 * @brief Concept checking if a type T is a valid field wrapper instance.
 *
 * Must be a Crunch::messages::Field or ArrayField.
 * For Field, validate that its inner type is valid.
 * We reuse the ValidElementType concept because
 * all valid Array elements are valid fields.
 *
 * @note FieldType is a type exposed by all Crunch top-level field types -
 * Field, ArrayField, and MapField. It is used both in this concept to assert
 * that a field is a valid Crunch field, and by serialization protocols to
 * create compile-time branching logic based on a field's underlying type.
 */
template <typename T>
concept ValidField =
    messages::is_array_field_v<std::remove_cvref_t<T>> ||
    messages::is_map_field_v<std::remove_cvref_t<T>> ||
    (messages::is_field_v<std::remove_cvref_t<T>> &&
     ValidElementType<typename std::remove_cvref_t<T>::FieldType>);

/// @cond INTERNAL

template <typename Tuple>
concept tuple_members_are_valid_fields = requires {
    std::apply([]<typename... Ts>(Ts&&...)
                   requires(ValidField<Ts> && ...)
               {},
               std::declval<Tuple>());
};

template <FieldId... Ids>
struct has_duplicates;

template <>
struct has_duplicates<> : std::false_type {};

template <FieldId Head, FieldId... Tail>
struct has_duplicates<Head, Tail...> {
    static constexpr bool value =
        ((Head == Tail) || ...) || has_duplicates<Tail...>::value;
};

template <typename Tuple>
concept has_unique_field_ids =
    []<std::size_t... Is>(std::index_sequence<Is...>) {
        return !has_duplicates<std::remove_cvref_t<
            std::tuple_element_t<Is, Tuple>>::field_id...>::value;
    }(std::make_index_sequence<std::tuple_size_v<Tuple>>{});

template <typename Message>
concept HasConstexprValidate = requires(const Message& m) {
    {
        std::bool_constant<(Message{}.Validate(), true)>()
    } -> std::same_as<std::true_type>;
};

template <typename Message>
concept HasConstexprGetFields = requires {
    {
        std::bool_constant<(Message{}.get_fields(), true)>()
    } -> std::same_as<std::true_type>;
};
/// @endcond

/**
 * @brief Concept ensuring a type is a fully valid CrunchMessage.
 *
 * Checks:
 * 1. Regular type (copyable, default constructible, etc).
 * 2. Has `message_id` and `get_fields()`.
 * 3. All fields in `get_fields()` are valid.
 * 4. Field IDs are unique.
 * 5. Has a `Validate()` method returning `std::optional<Error>`.
 */
template <typename Message>
concept CrunchMessage =
    std::regular<Message> && HasConstexprGetFields<Message> &&
    HasCrunchMessageInterface<Message> &&
    tuple_members_are_valid_fields<decltype(Message{}.get_fields())> &&
    has_unique_field_ids<decltype(Message{}.get_fields())> &&
    HasConstexprValidate<Message>;

}  // namespace Crunch::messages
