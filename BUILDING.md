# Building packages

I have updated `build.py` to be used with HopToDesk, it helps to create all the OS packages. I have tested deb and arch,
how to run:

    VCPKG=$HOME/vcpkg python build.py

This will generate installable package for the current platform.

# Build errors help

* If you are getting build errors related to scrap or opus, check VCPKG_ROOT is set or not.
* pynput_service.py file is not available in this repo
* cargo-deb works better than cargo-bundle.

# Current Issues

* Desktop icons are not generated. Will fix
* systemd script can be integrated to debian package. Which will reduce the build code