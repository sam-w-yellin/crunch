#define CATCH_CONFIG_RUNNER
#include <catch2/catch_session.hpp>

int main(int argc, char* argv[]) {
    Catch::Session session;
    int returnCode = session.run(argc, argv);
    return returnCode;
}
