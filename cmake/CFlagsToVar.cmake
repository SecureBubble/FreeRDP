function(CFlagsToVar NAME)
	set(C_FLAGS ${CMAKE_C_FLAGS})
	if (CMAKE_BUILD_TYPE)
	    string(TOUPPER "${CMAKE_BUILD_TYPE}" CAPS_BUILD_TYPE)
	    string(APPEND C_FLAGS " ${CMAKE_C_FLAGS_${CAPS_BUILD_TYPE}}")
	endif()
	string(REPLACE "\$" "\\\$" C_FLAGS "${C_FLAGS}")
	string(REPLACE "\"" "\\\"" C_FLAGS "${C_FLAGS}")
	set(${NAME} ${C_FLAGS} PARENT_SCOPE)
endfunction()

