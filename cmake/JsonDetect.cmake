include(CMakeDependentOption)

option(WITH_JSON_DISABLED "Build without any JSON support" OFF)
cmake_dependent_option(
  WITH_CJSON_REQUIRED "Build with cJSON (fail if not found)" OFF "NOT WITH_JSON_DISABLED;NOT WITH_JSONC_REQUIRED" OFF
)
cmake_dependent_option(
  WITH_JSONC_REQUIRED "Build with JSON-C (fail if not found)" OFF "NOT WITH_JSON_DISABLED;NOT WITH_CJSON_REQUIRED" OFF
)
if(NOT WITH_JSON_DISABLED)
  if(NOT WITH_JSONC_REQUIRED)
    find_package(cJSON)

    # Fallback detection:
    # older ubuntu releases did not ship CMake or pkg-config files
    # for cJSON. Be optimistic and try pkg-config and as last resort
    # try manual detection
    if(NOT CJSON_FOUND)
      find_package(PkgConfig)
      if(PKG_CONFIG_FOUND)
        pkg_check_modules(CJSON libcjson)
      endif()

      if(NOT CJSON_FOUND)
        find_path(CJSON_INCLUDE_DIRS NAMES cjson/cJSON.h)
        find_library(CJSON_LIBRARIES NAMES cjson)
        if(NOT "${CJSON_LIBRARIES}" STREQUAL "CJSON_LIBRARIES-NOTFOUND" AND NOT "${CJSON_INCLUDE_DIRS}" STREQUAL
                                                                            "CJSON_INCLUDE_DIRS-NOTFOUND"
        )
          set(CJSON_FOUND ON)
        endif()
      endif()
    endif()

    if(WITH_CJSON_REQUIRED)
      if(NOT CJSON_FOUND)
        message(FATAL_ERROR "cJSON was requested but not found")
      endif()
    endif()
  else()
    unset(CJSON_FOUND)
  endif()

  if(WITH_JSONC_REQUIRED)
    find_package(JSONC REQUIRED)
  elseif(NOT WITH_CJSON_REQUIRED)
    find_package(JSONC)
  endif()

  if(WITH_CJSON_REQUIRED)
    unset(JSONC_FOUND)
  endif()

  if(NOT JSONC_FOUND AND NOT CJSON_FOUND)
    if(WITH_CJSON_REQUIRED OR WITH_JSONC_REQUIRED)
      message(FATAL_ERROR "cJSON (${WITH_CJSON_REQUIRED}) or json-c (${WITH_JSONC_REQUIRED}) required but not found")
    endif()
    set(WITH_WINPR_JSON OFF CACHE INTERNAL "internal")
    message("compiling without JSON support. Install cJSON or json-c to enable")
  endif()
else()
  set(WITH_WINPR_JSON OFF CACHE INTERNAL "internal")
  message("forced compile without JSON support. Set -DWITH_JSON_DISABLED=OFF to enable compile time detection")
endif()
