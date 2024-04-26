add_requires("magic_enum")
add_rules("mode.debug")


set_languages("c++20")

target("server")
    set_kind("binary")
    add_files("src/server/*.cpp")
    add_files("src/*.cpp")
    add_includedirs("include")
    add_ldflags("-luring")

target("client")
    set_kind("binary")
    add_files("src/client/*.cpp")
    add_files("src/*.cpp")
    add_includedirs("include")
