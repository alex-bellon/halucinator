HALUCINATOR_ROOT="$HOME/halucinator"

cd $HALUCINATOR_ROOT
./install_deps.sh

VIRT_ENV="halucinator"
python3 -m venv ~/.virtualenvs/"$VIRT_ENV"

export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3
export WORKON_HOME=$HOME/.virtualenvs
export VIRTUALENVWRAPPER_VIRTUALENV=$HOME/.local/bin/virtualenv
source /usr/local/bin/virtualenvwrapper.sh

pip install -r src/requirements.txt
pip install -e src

git clone https://github.com/alex-bellon/avatar2 $HALUCINATOR_ROOT/deps/avatar2
git clone https://github.com/alex-bellon/avatar-qemu.git $HALUCINATOR_ROOT/deps/avatar2/targets/avatar-qemu

cd $HALUCINATOR_ROOT/deps/avatar2
pip install -e .
cd $HALUCINATOR_ROOT/deps/avatar2/targets
./build_qemu.sh

export HALUCINATOR_QEMU_ARM=$HALUCINATOR_ROOT/deps/avatar2/targets/build/qemu/arm-softmmu/qemu-system-arm
export HALUCINATOR_QEMU_ARM64=$HALUCINATOR_ROOT/deps/avatar2/targets/build/qemu/aarch64-softmmu/qemu-system-aarch64

sudo ln /usr/bin/gdb-multiarch /usr/bin/arm-none-eabi-gdb
