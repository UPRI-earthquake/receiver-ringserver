
DIRS = curl-8.1.1 jansson-2.12 pcre mxml libmseed src

# Test for Makefile/makefile and run make, run configure if it exists
# and no Makefile does.

# As a special case for pcre do not pass targets except "clean".

all clean install ::
	@for d in $(DIRS) ; do \
	  if [ ! -f $$d/Makefile -a ! -f $$d/makefile ] ; then \
	    if [ -x $$d/configure -a "$$d" = "pcre" ] ; then \
	      echo "Running configure in $$d" ; \
              ( cd $$d && touch -c * ) ; \
	      ( cd $$d && ./configure --with-link-size=4 --disable-shared --enable-static --disable-cpp ) ; \
	    elif [ -x $$d/configure -a "$$d" = "mxml" ] ; then \
	       echo "Running configure in $$d" ; \
	      ( cd $$d && ./configure --disable-shared --enable-threads ) ; \
	    elif [ -x $$d/configure -a "$$d" = "curl-8.1.1" ] ; then \
	       echo "Running autoreconf & configure in $$d" ; \
	      ( cd $$d && autoreconf -fi && ./configure --disable-shared --with-openssl ) ; \
	    else \
	      echo "Running configure in $$d" ; \
	      ( cd $$d && ./configure ) ; \
	    fi ; \
	  fi ; \
	  echo "Running $(MAKE) $@ in $$d" ; \
	  if [ -f $$d/Makefile -o -f $$d/makefile ] ; then \
	    if [ "$$d" = "pcre" -a "$@" != "clean" ] ; then \
	      ( cd $$d && $(MAKE) ) ; \
	    else \
	      ( cd $$d && $(MAKE) $@ ) ; \
	    fi ; \
	  elif [ -d $$d ] ; \
	    then ( echo "ERROR: no Makefile/makefile in $$d for $(CC)" ) ; \
	  fi ; \
	done
	
