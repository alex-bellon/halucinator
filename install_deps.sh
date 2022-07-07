#!/bin/bash
# . /etc/bash_completion
set -e 
set -x

DISTRO=none

if [ -f /etc/os-release ]; then
  . /etc/os-release
  DISTRO="${ID_LIKE:-$ID}"
fi

case $DISTRO in
  "arch" )
    sudo pacman -S ethtool tk gdb tcpdump python-pip \
                   python-virtualenv cmake gcc base-devel pixman
    ;;
  "debian" | "ubuntu" )
    sudo apt-get install -y ethtool python-tk gdb-multiarch tcpdump \
                            python3-pip python3-venv cmake g++ \
                            build-essential libpixman-1-dev \
			    pkg-config
    ;;
  *) echo "Distro not supported" ;;
esac

sudo pip3 install virtualenv virtualenvwrapper

# VIRT_ENV="halucinator"
# python3 -m venv ~/.virtualenvs/"$VIRT_ENV"

# # Activate the virtual environment (workon doesn't work in the script)
# echo "================================================"
# echo "$VIRT_ENV virt environment created now run:" 
# echo ""
# echo "source ~/.virtualenvs/$VIRT_ENV/bin/activate"
# echo "./setup.sh"
