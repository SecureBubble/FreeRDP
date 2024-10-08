
#include <winpr/crt.h>

#include <winpr/version.h>
#include <winpr/winpr.h>

int TestVersion(int argc, char* argv[])
{
	const char* version = NULL;
	const char* git = NULL;
	const char* build = NULL;
	int major = 0;
	int minor = 0;
	int revision = 0;
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);
	winpr_get_version(&major, &minor, &revision);

	if (major != WINPR_VERSION_MAJOR)
		return -1;

	if (minor != WINPR_VERSION_MINOR)
		return -1;

	if (revision != WINPR_VERSION_REVISION)
		return -1;

	version = winpr_get_version_string();

	if (!version)
		return -1;

	git = winpr_get_build_revision();

	if (!git)
		return -1;

	if (strncmp(git, WINPR_GIT_REVISION, sizeof(WINPR_GIT_REVISION)) != 0)
		return -1;

	build = winpr_get_build_config();

	if (!build)
		return -1;

	return 0;
}
