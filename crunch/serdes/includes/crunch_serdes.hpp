#pragma once

#include <concepts>
#include <crunch_messages.hpp>
#include <cstddef>
#include <optional>
#include <span>
#include <type_traits>

namespace Crunch {

/**
 * @brief Concept defining a Serialization/Deserialization policy.
 *
 * A SerdesPolicy knows how to serialize a specific Message type. It must
 * provide:
 * - `Size<Message>()`: Returns the maximum serialized size. Must be constexpr.
 * - `GetFormat()`: Returns the format of the message. Must be constexpr.
 * - `Serialize(msg, output)`: Serializes the message into the output span. Must
 * be `constexpr`.
 * - `Deserialize(input, msg)`: Deserializes the input span into the message
 * object. Must be `constexpr`.
 *
 * @note The `Deserialize` and `Serialize` functions must be `constexpr`.
 * However, this requirement is not enforced by the concept because the
 * arguments provided in the requires-expression are not constant expressions,
 * preventing verification via `std::bool_constant`.
 *
 * @note Serialize passes the entire buffer - including the already-parsed
 * header - to the policy. The policy generally should just skip the header
 * bytes when serializing. I wasn't sure if there may be a good reason in the
 * future to give the policy more context on the header and wanted to hedge my
 * bets.
 */
template <typename Policy, typename Message>
concept SerdesPolicy =
    messages::CrunchMessage<Message> &&
    requires(const Message& msg, std::span<std::byte> output,
             std::span<const std::byte> input) {
        {
            std::bool_constant<(Policy::template Size<Message>(), true)>()
        } -> std::same_as<std::true_type>;
        { Policy::template Size<Message>() } -> std::same_as<std::size_t>;

        { Policy::Serialize(msg, output) } -> std::same_as<std::size_t>;
        {
            Policy::Deserialize(input, const_cast<Message&>(msg))
        } -> std::same_as<std::optional<Error>>;
        {
            std::bool_constant<(Policy::GetFormat(), true)>()
        } -> std::same_as<std::true_type>;
        { Policy::GetFormat() } -> std::same_as<Format>;
    };

}  // namespace Crunch
