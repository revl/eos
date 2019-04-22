if [ $1 == 1 ]; then ANSWER=1; else ANSWER=0; fi

OS_VER=$( grep VERSION_ID /etc/os-release | cut -d'=' -f2 | sed 's/[^0-9\.]//gI' )
OS_MAJ=$(echo "${OS_VER}" | cut -d'.' -f1)
OS_MIN=$(echo "${OS_VER}" | cut -d'.' -f2)

MEM_MEG=$( free -m | sed -n 2p | tr -s ' ' | cut -d\  -f2 || cut -d' ' -f2 )
CPU_SPEED=$( lscpu | grep -m1 "MHz" | tr -s ' ' | cut -d\  -f3 || cut -d' ' -f3 | cut -d'.' -f1 )
CPU_CORE=$( nproc )
MEM_GIG=$(( ((MEM_MEG / 1000) / 2) ))
export JOBS=$(( MEM_GIG > CPU_CORE ? CPU_CORE : MEM_GIG ))

DISK_INSTALL=$(df -h . | tail -1 | tr -s ' ' | cut -d\  -f1 || cut -d' ' -f1)
DISK_TOTAL_KB=$(df . | tail -1 | awk '{print $2}')
DISK_AVAIL_KB=$(df . | tail -1 | awk '{print $4}')
DISK_TOTAL=$(( DISK_TOTAL_KB / 1048576 ))
DISK_AVAIL=$(( DISK_AVAIL_KB / 1048576 ))

printf "\\nOS name: ${OS_NAME}\\n"
printf "OS Version: ${OS_VER}\\n"
printf "CPU speed: ${CPU_SPEED}Mhz\\n"
printf "CPU cores: %s\\n" "${CPU_CORE}"
printf "Physical Memory: ${MEM_MEG} Mgb\\n"
printf "Disk install: ${DISK_INSTALL}\\n"
printf "Disk space total: ${DISK_TOTAL%.*}G\\n"
printf "Disk space available: ${DISK_AVAIL%.*}G\\n"

PINNED_TOOLCHAIN=-DCMAKE_TOOLCHAIN_FILE=$BUILD_DIR/pinned_toolchain.cmake

if [ "${MEM_MEG}" -lt 7000 ]; then
	printf "Your system must have 7 or more Gigabytes of physical memory installed.\\n"
	printf "Exiting now.\\n"
	exit 1
fi

case "${OS_NAME}" in
	"Linux Mint")
		if [ "${OS_MAJ}" -lt 18 ]; then
			printf "You must be running Linux Mint 18.x or higher to install EOSIO.\\n"
			printf "Exiting now.\\n"
			exit 1
		fi
	;;
	"Ubuntu")
		. /etc/lsb-release
		if [ "${DISTRIB_CODENAME}" != "xenial" -a "${DISTRIB_CODENAME}" != "bionic" ]; then
			echo "The only Ubuntu versions this script supports are Ubuntu 16.04 and 18.04"
			echo "Exiting now."
			exit 1
		fi
		# UBUNTU 18 doesn't have MONGODB 3.6.3
		if [ $OS_MAJ -gt 16 ]; then
			export MONGODB_VERSION=4.1.1
		fi
		# We have to re-set this with the new version
		export MONGODB_ROOT=${OPT_LOCATION}/mongodb-${MONGODB_VERSION}
	;;
	"Debian")
		if [ $OS_MAJ -lt 10 ]; then
			printf "You must be running Debian 10 to install EOSIO, and resolve missing dependencies from unstable (sid).\n"
			printf "Exiting now.\n"
			exit 1
	fi
	;;
esac

if [ "${DISK_AVAIL%.*}" -lt "${DISK_MIN}" ]; then
	printf "You must have at least %sGB of available storage to install EOSIO.\\n" "${DISK_MIN}"
	printf "Exiting now.\\n"
	exit 1
fi

# llvm-4.0 is installed into /usr/lib/llvm-4.0
if [ ! PIN_COMPILER ]; then
   llvm4_deps=(llvm-4.0 libclang-4.0-dev)
fi

DEP_ARRAY=(
   git make automake libbz2-dev libssl-dev doxygen graphviz \
   libgmp3-dev autotools-dev build-essential libicu-dev python2.7 python2.7-dev python3 python3-dev \
   autoconf libtool curl zlib1g-dev sudo ruby libusb-1.0-0-dev libcurl4-gnutls-dev pkg-config
)

DEP_ARRAY+=$llvm4_deps

COUNT=1
DISPLAY=""
DEP=""

if [[ "${ENABLE_CODE_COVERAGE}" == true ]]; then
	DEP_ARRAY+=(lcov)
fi

if [ $ANSWER != 1 ]; then read -p "Do you wish to update repositories with apt-get update? (y/n) " ANSWER; fi
case $ANSWER in
	1 | [Yy]* )
		if ! sudo apt-get update; then
			printf " - APT update failed.\\n"
			exit 1;
		else
			printf " - APT update complete.\\n"
		fi
	;;
	[Nn]* ) echo "Proceeding without update!";;
	* ) echo "Please type 'y' for yes or 'n' for no."; exit;;
esac

printf "\\nChecking for installed dependencies...\\n"
for (( i=0; i<${#DEP_ARRAY[@]}; i++ )); do
	pkg=$( dpkg -s "${DEP_ARRAY[$i]}" 2>/dev/null | grep Status | tr -s ' ' | cut -d\  -f4 )
	if [ -z "$pkg" ]; then
		DEP=$DEP" ${DEP_ARRAY[$i]} "
		DISPLAY="${DISPLAY}${COUNT}. ${DEP_ARRAY[$i]}\\n"
		printf " - Package %s${bldred} NOT${txtrst} found!\\n" "${DEP_ARRAY[$i]}"
		(( COUNT++ ))
	else
		printf " - Package %s found.\\n" "${DEP_ARRAY[$i]}"
		continue
	fi
done
if [ "${COUNT}" -gt 1 ]; then
	printf "\\nThe following dependencies are required to install EOSIO:\\n"
	printf "${DISPLAY}\\n\\n"
	if [ $ANSWER != 1 ]; then read -p "Do you wish to install these packages? (y/n) " ANSWER; fi
	case $ANSWER in
		1 | [Yy]* )
			if ! sudo apt-get -y install ${DEP}; then
				printf " - APT dependency failed.\\n"
				exit 1
			else
				printf " - APT dependencies installed successfully.\\n"
			fi
		;;
		[Nn]* ) echo "User aborting installation of required dependencies, Exiting now."; exit;;
		* ) echo "Please type 'y' for yes or 'n' for no."; exit;;
	esac
else
	printf " - No required APT dependencies to install.\\n"
fi


printf "\\n"


printf "Checking CMAKE installation...\\n"
if [ ! -e $CMAKE ]; then
	printf "Installing CMAKE...\\n"
	curl -LO https://cmake.org/files/v$CMAKE_VERSION_MAJOR.$CMAKE_VERSION_MINOR/cmake-$CMAKE_VERSION.tar.gz \
	&& tar -xzf cmake-$CMAKE_VERSION.tar.gz \
	&& cd cmake-$CMAKE_VERSION \
	&& ./bootstrap --prefix=$PREFIX \
	&& make -j"${JOBS}" \
	&& make install \
	&& cd .. \
	&& rm -f cmake-$CMAKE_VERSION.tar.gz \
	|| exit 1
	printf " - CMAKE successfully installed @ ${CMAKE} \\n"
else
	printf " - CMAKE found @ ${CMAKE}.\\n"
fi
if [ $? -ne 0 ]; then exit -1; fi


printf "\\n"

if $PIN_COMPILER; then
   printf "Checking Clang 8 support...\\n"
   if [ ! -d $CLANG8_ROOT ]; then
      printf "Installing Clang 8...\\n"
      cd ${TMP_LOCATION} \
      && git clone --depth 1 --single-branch --branch $PINNED_COMPILER_BRANCH https://git.llvm.org/git/llvm.git clang8 && cd clang8 \
      && git checkout $PINNED_COMPILER_LLVM_COMMIT \
      && cd tools \
      && git clone --depth 1 --single-branch --branch $PINNED_COMPILER_BRANCH https://git.llvm.org/git/lld.git \
      && cd lld && git checkout $PINNED_COMPILER_LLD_COMMIT && cd ../ \
      && git clone --depth 1 --single-branch --branch $PINNED_COMPILER_BRANCH https://git.llvm.org/git/polly.git \
      && cd polly && git checkout $PINNED_COMPILER_POLLY_COMMIT && cd ../ \
      && git clone --depth 1 --single-branch --branch $PINNED_COMPILER_BRANCH https://git.llvm.org/git/clang.git clang && cd clang/tools \
      && git checkout $PINNED_COMPILER_CLANG_VERSION \
      && mkdir extra && cd extra \
      && git clone --depth 1 --single-branch --branch $PINNED_COMPILER_BRANCH https://git.llvm.org/git/clang-tools-extra.git \
      && cd clang-tools-extra && git checkout $PINNED_COMPILER_CLANG_TOOLS_EXTRA_COMMIT && cd .. \
      && cd ../../../../projects \
      && git clone --depth 1 --single-branch --branch $PINNED_COMPILER_BRANCH https://git.llvm.org/git/libcxx.git \
      && cd libcxx && git checkout $PINNED_COMPILER_LIBCXX_COMMIT && cd ../ \
      && git clone --depth 1 --single-branch --branch $PINNED_COMPILER_BRANCH https://git.llvm.org/git/libcxxabi.git \
      && cd libcxxabi && git checkout $PINNED_COMPILER_LIBCXXABI_COMMIT && cd ../ \
      && git clone --depth 1 --single-branch --branch $PINNED_COMPILER_BRANCH https://git.llvm.org/git/libunwind.git \
      && cd libunwind && git checkout $PINNED_COMPILER_LIBUNWIND_COMMIT && cd ../ \
      && git clone --depth 1 --single-branch --branch $PINNED_COMPILER_BRANCH https://git.llvm.org/git/compiler-rt.git \
      && cd compiler-rt && git checkout $PINNED_COMPILER_COMPILER_RT_COMMIT && cd ../ \
      && cd ${TMP_LOCATION}/clang8 \
      && mkdir build && cd build \
      && $CMAKE -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX="${CLANG8_ROOT}" -DLLVM_BUILD_EXTERNAL_COMPILER_RT=ON -DLLVM_BUILD_LLVM_DYLIB=ON -DLLVM_ENABLE_LIBCXX=ON -DLLVM_ENABLE_RTTI=ON -DLLVM_INCLUDE_DOCS=OFF -DLLVM_OPTIMIZED_TABLEGEN=ON -DLLVM_TARGETS_TO_BUILD=all -DCMAKE_BUILD_TYPE=Release .. \
      && make -j"${JOBS}" \
      && make install \
      && rm -rf ${TMP_LOCATION}/clang8 \
      && cd ../.. \
      || exit 1

      printf " - Clang 8 successfully installed @ ${CLANG8_ROOT}\\n"
   else
      printf " - Clang 8 found @ ${CLANG8_ROOT}.\\n"
   fi
   if [ $? -ne 0 ]; then exit -1; fi

   printf "\\n"

   printf "Checking LLVM 4 installation...\\n"
   if [ ! -d $OPT_LOCATION/llvm4 ]; then
      printf "Installing LLVM 4...\\n"
      curl -LO http://releases.llvm.org/4.0.0/llvm-4.0.0.src.tar.xz && tar -xf llvm-4.0.0.src.tar.xz \
      && cd llvm-4.0.0.src && mkdir -p build && cd build \
      && $CMAKE -DCMAKE_INSTALL_PREFIX=$OPT_LOCATION/llvm4 -DLLVM_TARGETS_TO_BUILD=host -DLLVM_BUILD_TOOLS=false -DLLVM_ENABLE_RTTI=1 -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=$BUILD_DIR/pinned_toolchain.cmake .. \
      && make -j"${JOBS}" install \
      || exit -1
      printf "Installed LLVM 4 @ ${OPT_LOCATION}/llvm4"
   fi

   cd $SRC_LOCATION
   printf "Checking zlib library (${BOOST_VERSION}) installation...\\n"
   if [ ! -d $OPT_LOCATION/zlib ]; then
      printf "Installing zlib...\\n"
      curl -LO https://www.zlib.net/zlib-1.2.11.tar.gz && tar -xf zlib-1.2.11.tar.gz \
      && cd zlib-1.2.11 && mkdir build && cd build \
      && ../configure --prefix=$OPT_LOCATION/zlib \
      && make -j"${JOBS}" install \
      || exit -1
   fi

   cd $SRC_LOCATION
   printf "Checking Boost library (${BOOST_VERSION}) installation...\\n"
   BOOSTVERSION=$( grep "#define BOOST_VERSION" "$BOOST_ROOT/include/boost/version.hpp" 2>/dev/null | tail -1 | tr -s ' ' | cut -d\  -f3 )
   if [ "${BOOSTVERSION}" != "${BOOST_VERSION_MAJOR}0${BOOST_VERSION_MINOR}0${BOOST_VERSION_PATCH}" ]; then
      printf "Installing Boost library...\\n"
      curl -LO https://dl.bintray.com/boostorg/release/${BOOST_VERSION_MAJOR}.${BOOST_VERSION_MINOR}.${BOOST_VERSION_PATCH}/source/boost_$BOOST_VERSION.tar.bz2 \
      && tar -xjf boost_$BOOST_VERSION.tar.bz2 \
      && cd $BOOST_ROOT \
      && printf "using clang : 8.0 : ${CLANG8_ROOT}/bin/clang++ : <cxxflags>\"-D__STRICT_ANSI__ -stdlib=libc++ -std=c++17 -nostdinc++ -I${CLANG8_ROOT}/include/c++/v1\";" &> clang8.jam \
      && ./bootstrap.sh --prefix=$BOOST_ROOT \
      && ./b2 toolset=clang cxxflags="-stdlib=libc++ -D__STRICT_ANSI__ -nostdinc++ -I${CLANG8_ROOT}/include/c++/v1" linkflags="-stdlib=libc++" link=static threading=multi --with-iostreams --with-date_time --with-filesystem --with-system --with-program_options --with-chrono --with-test -q -j"${JOBS}" -sZLIB_LIBRARY_PATH="${OPT_LOCATION}/zlib/lib" -sZLIB_INCLUDE="${OPT_LOCATION}/zlib/include" -sZLIB_SOURCE="${SRC_LOCATION}/zlib-1.2.11" install \
      && cd .. \
      && rm -f boost_$BOOST_VERSION.tar.bz2 \
      && rm -rf $BOOST_LINK_LOCATION \
      && ln -s $BOOST_ROOT $BOOST_LINK_LOCATION \
      || exit 1
      printf " - Boost library successfully installed @ ${BOOST_ROOT} (Symlinked to ${BOOST_LINK_LOCATION}).\\n"
   else
      printf " - Boost library found with correct version @ ${BOOST_ROOT} (Symlinked to ${BOOST_LINK_LOCATION}).\\n"
   fi
   if [ $? -ne 0 ]; then exit -1; fi
   
   printf "\\n"
else
   printf "Checking Boost library (${BOOST_VERSION}) installation...\\n"
   BOOSTVERSION=$( grep "#define BOOST_VERSION" "$BOOST_ROOT/include/boost/version.hpp" 2>/dev/null | tail -1 | tr -s ' ' | cut -d\  -f3 )
   if [ "${BOOSTVERSION}" != "${BOOST_VERSION_MAJOR}0${BOOST_VERSION_MINOR}0${BOOST_VERSION_PATCH}" ]; then
      printf "Installing Boost library...\\n"
      curl -LO https://dl.bintray.com/boostorg/release/${BOOST_VERSION_MAJOR}.${BOOST_VERSION_MINOR}.${BOOST_VERSION_PATCH}/source/boost_$BOOST_VERSION.tar.bz2 \
      && tar -xjf boost_$BOOST_VERSION.tar.bz2 \
      && cd $BOOST_ROOT \
      && ./bootstrap.sh --prefix=$BOOST_ROOT \
      && ./b2 -q -j"${JOBS}" install \
      && cd .. \
      && rm -f boost_$BOOST_VERSION.tar.bz2 \
      && rm -rf $BOOST_LINK_LOCATION \
      && ln -s $BOOST_ROOT $BOOST_LINK_LOCATION \
      || exit 1
      printf " - Boost library successfully installed @ ${BOOST_ROOT} (Symlinked to ${BOOST_LINK_LOCATION}).\\n"
   else
      printf " - Boost library found with correct version @ ${BOOST_ROOT} (Symlinked to ${BOOST_LINK_LOCATION}).\\n"
   fi
   if [ $? -ne 0 ]; then exit -1; fi

   printf "\\n"

   printf "Checking MongoDB installation...\\n"
   if [ ! -d $MONGODB_ROOT ]; then
      printf "Installing MongoDB into ${MONGODB_ROOT}...\\n"
      curl -OL http://downloads.mongodb.org/linux/mongodb-linux-x86_64-ubuntu$OS_MAJ$OS_MIN-$MONGODB_VERSION.tgz \
      && tar -xzf mongodb-linux-x86_64-ubuntu$OS_MAJ$OS_MIN-$MONGODB_VERSION.tgz \
      && mv $SRC_LOCATION/mongodb-linux-x86_64-ubuntu$OS_MAJ$OS_MIN-$MONGODB_VERSION $MONGODB_ROOT \
      && touch $MONGODB_LOG_LOCATION/mongod.log \
      && rm -f mongodb-linux-x86_64-ubuntu$OS_MAJ$OS_MIN-$MONGODB_VERSION.tgz \
      && cp -f $REPO_ROOT/scripts/mongod.conf $MONGODB_CONF \
      && mkdir -p $MONGODB_DATA_LOCATION \
      && rm -rf $MONGODB_LINK_LOCATION \
      && rm -rf $BIN_LOCATION/mongod \
      && ln -s $MONGODB_ROOT $MONGODB_LINK_LOCATION \
      && ln -s $MONGODB_LINK_LOCATION/bin/mongod $BIN_LOCATION/mongod \
      || exit 1
      printf " - MongoDB successfully installed @ ${MONGODB_ROOT} (Symlinked to ${MONGODB_LINK_LOCATION}).\\n"
   else
      printf " - MongoDB found with correct version @ ${MONGODB_ROOT} (Symlinked to ${MONGODB_LINK_LOCATION}).\\n"
   fi
   if [ $? -ne 0 ]; then exit -1; fi
   printf "Checking MongoDB C driver installation...\\n"
   if [ ! -d $MONGO_C_DRIVER_ROOT ]; then
      if [ ! $BUILD_CLANG8 ]; then
         PINNED_TOOLCHAIN=""
      fi
      printf "Installing MongoDB C driver...\\n"
      curl -LO https://github.com/mongodb/mongo-c-driver/releases/download/$MONGO_C_DRIVER_VERSION/mongo-c-driver-$MONGO_C_DRIVER_VERSION.tar.gz \
      && tar -xzf mongo-c-driver-$MONGO_C_DRIVER_VERSION.tar.gz \
      && cd mongo-c-driver-$MONGO_C_DRIVER_VERSION \
      && mkdir -p cmake-build \
      && cd cmake-build \
      && $CMAKE -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PREFIX -DENABLE_BSON=ON -DENABLE_SSL=OPENSSL -DENABLE_AUTOMATIC_INIT_AND_CLEANUP=OFF -DENABLE_STATIC=ON $PINNED_TOOLCHAIN .. \
      && make -j"${JOBS}" \
      && make install \
      && cd ../.. \
      && rm mongo-c-driver-$MONGO_C_DRIVER_VERSION.tar.gz \
      || exit 1
      printf " - MongoDB C driver successfully installed @ ${MONGO_C_DRIVER_ROOT}.\\n"
   else
      printf " - MongoDB C driver found with correct version @ ${MONGO_C_DRIVER_ROOT}.\\n"
   fi

   if [ $? -ne 0 ]; then exit -1; fi
   printf "Checking MongoDB C++ driver installation...\\n"
   if [ ! -d $MONGO_CXX_DRIVER_ROOT ]; then
      if [ ! $BUILD_CLANG8 ]; then
         PINNED_TOOLCHAIN=""
      fi
      printf "Installing MongoDB C++ driver...\\n"
      curl -L https://github.com/mongodb/mongo-cxx-driver/archive/r$MONGO_CXX_DRIVER_VERSION.tar.gz -o mongo-cxx-driver-r$MONGO_CXX_DRIVER_VERSION.tar.gz \
      && tar -xzf mongo-cxx-driver-r${MONGO_CXX_DRIVER_VERSION}.tar.gz \
      && cd mongo-cxx-driver-r$MONGO_CXX_DRIVER_VERSION \
      && sed '111 s/count/static_cast<int64_t>(count)/' src/mongocxx/options/change_stream.cpp &> src/mongocxx/options/change_stream.cpp \
      && cd build \
      && $CMAKE -DBUILD_SHARED_LIBS=OFF -DCXX_CMAKE_FLAGS=-D_GLIBCXX_USE_CXX11_ABI=1 -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PREFIX $PINNED_TOOLCHAIN .. \
      && make -j"${JOBS}" VERBOSE=1 \
      && make install \
      && cd ../.. \
      && rm -f mongo-cxx-driver-r$MONGO_CXX_DRIVER_VERSION.tar.gz \
      || exit 1
      printf " - MongoDB C++ driver successfully installed @ ${MONGO_CXX_DRIVER_ROOT}.\\n"
   else
      printf " - MongoDB C++ driver found with correct version @ ${MONGO_CXX_DRIVER_ROOT}.\\n"
   fi
   if [ $? -ne 0 ]; then exit -1; fi


   printf "\\n"

   printf "Checking LLVM 4 support...\\n"
   if [ ! -d $LLVM_ROOT ]; then
      ln -s /usr/lib/llvm-4.0 $LLVM_ROOT \
      || exit 1
      printf " - LLVM successfully linked from /usr/lib/llvm-4.0 to ${LLVM_ROOT}\\n"
   else
      printf " - LLVM found @ ${LLVM_ROOT}.\\n"
   fi
   if [ $? -ne 0 ]; then exit -1; fi
fi

cd ..
printf "\\n"

function print_instructions() {
	return 0
}
