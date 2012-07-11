SET(SRC_LIST
testautoit.cpp)

ADD_EXECUTABLE(testautoit ${SRC_LIST})
TARGET_LINK_LIBRARIES(testautoit autoit_static)
TARGET_LINK_LIBRARIES(testautoit cppunit)
TARGET_LINK_LIBRARIES(testautoit filemap)
IF(WIN32)
#TARGET_LINK_LIBRARIES(testautoit version)
ELSE(WIN32)
TARGET_LINK_LIBRARIES(testautoit dl)
ENDIF(WIN32)

#install
INSTALL(TARGETS testautoit RUNTIME DESTINATION bin)


INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/test.bin
	DESTINATION bin/testautoit.config)
