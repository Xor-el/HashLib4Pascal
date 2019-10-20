#!/usr/bin/env python3
# Part of `travis-lazarus` (https://github.com/nielsAD/travis-lazarus)
# License: MIT

import sys
import os
import subprocess

OS_NAME=os.environ.get('TRAVIS_OS_NAME') or 'linux'
OS_PMAN={'linux': 'sudo apt-get', 'osx': 'brew', 'windows':'choco'}[OS_NAME]

LAZ_TMP_DIR=os.environ.get('LAZ_TMP_DIR') or 'lazarus_tmp'
LAZ_REL_DEF=os.environ.get('LAZ_REL_DEF') or {'linux':'amd64', 'qemu-arm':'amd64', 'qemu-arm-static':'amd64', 'osx':'i386', 'wine':'32', 'windows':'64'}
LAZ_BIN_SRC=os.environ.get('LAZ_BIN_SRC') or 'https://sourceforge.net/projects/lazarus/files/%(target)s/Lazarus%%20%(version)s/'
LAZ_BIN_TGT=os.environ.get('LAZ_BIN_TGT') or {
    'linux':           'Lazarus%%20Linux%%20%(release)s%%20DEB',
    'qemu-arm':        'Lazarus%%20Linux%%20%(release)s%%20DEB',
    'qemu-arm-static': 'Lazarus%%20Linux%%20%(release)s%%20DEB',
    'osx':             'Lazarus%%20Mac%%20OS%%20X%%20%(release)s',
    'wine':            'Lazarus%%20Windows%%20%(release)s%%20bits',
    'windows':         'Lazarus%%20Windows%%20%(release)s%%20bits'
}
DOWNLOAD_SCRIPT='download_script.sh'

def install_osx_dmg(dmg):
    try:
        # Mount .dmg file and parse (automatically determined) target volumes
        res = str(subprocess.check_output('sudo hdiutil attach %s | grep /Volumes/' % (dmg), shell=True), "utf-8")
        vol = ('/Volumes/' + l.strip().split('/Volumes/')[-1] for l in res.splitlines() if '/Volumes/' in l)
    except:
        return False

    # Install .pkg files with installer
    install_pkg = lambda v, f: os.system('sudo installer -pkg %s/%s -target /' % (v, f)) == 0

    for v in vol:
        try:
            if not all(map(lambda f: (not f.endswith('.pkg')) or install_pkg(v, f), os.listdir(v))):
                return False
        finally:
            # Unmount after installation
            os.system('hdiutil detach %s' % (v))

    return True

def install_lazarus_default():
    if OS_NAME == 'linux':
        # Make sure nogui is installed for headless runs
        pkg = 'lazarus lcl-nogui -y'
    elif OS_NAME == 'osx':
        # cask is already present in brew
        pkg = 'fpc && %s cask install fpcsrc lazarus' % (OS_PMAN)
    else:
        # Default to lazarus
        pkg = 'lazarus'
    return os.system('%s install %s' % (OS_PMAN, pkg)) == 0

def install_lazarus_version(ver,rel,env):
    # Download all files in directory for specified Lazarus version
    osn = env or OS_NAME
    tgt = LAZ_BIN_TGT[osn] % {'release': rel or LAZ_REL_DEF[osn]}
    src = LAZ_BIN_SRC % {'target': tgt, 'version': ver}

    # Create sourceforge download script
    sourceforce_script = '\n'.join([
        'wget -w 1 -np -m -A download %s' % (src),
        'grep -Rh refresh sourceforge.net/ | grep -o "https://[^\\?]*" > urllist',
        'while read url; do wget --content-disposition "${url}" -A .deb,.dmg,.exe -P %s; done < urllist' % (LAZ_TMP_DIR)
    ])
    with open(DOWNLOAD_SCRIPT,'w') as f:
        f.write(sourceforce_script)

    # Show download script for debug purpose
    os.system('cat %s' % (DOWNLOAD_SCRIPT))

    # Run the download script
    if os.system('chmod +x %s' % (DOWNLOAD_SCRIPT)) != 0:
        return False

    if os.system('sh ./%s' % (DOWNLOAD_SCRIPT)) != 0:
        return False

    if osn == 'wine':
        # Install wine and Xvfb
        if os.system('sudo dpkg --add-architecture i386 && %s update && %s install xvfb wine' % (OS_PMAN, OS_PMAN)) != 0:
            return False

        # Initialize virtual display and wine directory
        if os.system('Xvfb %s & sleep 3 && wineboot -i' % (os.environ.get('DISPLAY') or '')) != 0:
            return False

        # Install basic Wine prerequisites, ignore failure
        os.system('winetricks -q corefonts')

        # Install all .exe files with wine
        process_file = lambda f: (not f.endswith('.exe')) or os.system('wine %s /VERYSILENT /DIR="c:\\lazarus"' % (f)) == 0
    elif osn == 'qemu-arm' or osn == 'qemu-arm-static':
        # Install qemu and arm cross compiling utilities
        if os.system('%s install libgtk2.0-dev qemu-user qemu-user-static binutils-arm-linux-gnueabi gcc-arm-linux-gnueabi' % (OS_PMAN)) != 0:
            return False

        # Install all .deb files (for linux) and cross compile later
        process_file = lambda f: (not f.endswith('.deb')) or os.system('sudo dpkg --force-overwrite -i %s' % (f)) == 0
    elif osn == 'linux':
        # Install dependencies
        if os.system('%s install libgtk2.0-dev' % (OS_PMAN)) != 0:
            return False

        # Install all .deb files
        process_file = lambda f: (not f.endswith('.deb')) or os.system('sudo dpkg --force-overwrite -i %s' % (f)) == 0
    elif osn == 'osx':
        # Install all .dmg files
        process_file = lambda f: (not f.endswith('.dmg')) or install_osx_dmg(f)
    elif osn == 'windows':
        # Install lazarus .exe files
        process_file = lambda f: (not f.endswith('.exe')) or os.system('%s /VERYSILENT /DIR="c:\\lazarus"' % (f)) == 0
    else:
        return False

    # Process all downloaded files
    if not all(map(lambda f: process_file(os.path.join(LAZ_TMP_DIR, f)), sorted(os.listdir(LAZ_TMP_DIR)))):
        return False

    if osn == 'wine':
        # Set wine Path (persistently) to include Lazarus binary directory
        if os.system('wine cmd /C reg add HKEY_CURRENT_USER\\\\Environment /v PATH /t REG_SZ /d "%PATH%\\;c:\\\\lazarus"') != 0:
            return False

        # Redirect listed executables so they execute in wine
        for alias in ('fpc', 'lazbuild', 'lazarus'):
            os.system('echo "#!/usr/bin/env bash \nwine %(target)s \$@" | sudo tee %(name)s > /dev/null && sudo chmod +x %(name)s' % {
                'target': str(subprocess.check_output("find $WINEPREFIX -iname '%s.exe' | head -1 " % (alias), shell=True).strip(), "utf-8"),
                'name': '/usr/bin/%s' % (alias)
            })
    elif osn == 'qemu-arm' or osn == 'qemu-arm-static':
        fpcv = str(subprocess.check_output('fpc -iV', shell=True).strip(), "utf-8")
        gccv = str(subprocess.check_output('arm-linux-gnueabi-gcc -dumpversion', shell=True).strip(), "utf-8")
        opts = ' '.join([
            'CPU_TARGET=arm',
            'OS_TARGET=linux',
            'BINUTILSPREFIX=arm-linux-gnueabi-',
            # 'CROSSOPT="-CpARMV7A -CfVFPV3_D16"',
            'OPT=-dFPC_ARMEL',
            'INSTALL_PREFIX=/usr'
        ])

        # Compile ARM cross compiler
        if os.system('cd /usr/share/fpcsrc/%s && sudo make clean crossall crossinstall %s' % (fpcv, opts)) != 0:
            return False
        
        # Symbolic link to update default FPC cross compiler for ARM
        if os.system('sudo ln -sf /usr/lib/fpc/%s/ppcrossarm /usr/bin/ppcarm' % (fpcv)) != 0:
            return False

        # Update config file with paths to ARM libraries
        config = '\n'.join([
            '#INCLUDE /etc/fpc.cfg',
            '#IFDEF CPUARM',
            '-Xd','-Xt',
            '-XParm-linux-gnueabi-',
            '-Fl/usr/arm-linux-gnueabi/lib',
            '-Fl/usr/lib/gcc/arm-linux-gnueabi/%s' % (gccv),
            '-Fl/usr/lib/gcc-cross/arm-linux-gnueabi/%s' % (gccv),
            # '-CpARMV7A', '-CfVFPV3_D16',
            '#ENDIF',
            ''
        ])
        with open(os.path.expanduser('~/.fpc.cfg'),'w') as f:
            f.write(config)

    return True

def install_lazarus(ver=None,rel=None,env=None):
    return install_lazarus_version(ver,rel,env) if ver else install_lazarus_default()

def main():
    os.system('%s update' % (OS_PMAN))
    return install_lazarus(os.environ.get('LAZ_VER'),os.environ.get('LAZ_REL'),os.environ.get('LAZ_ENV'))

if __name__ == '__main__':
    sys.exit(int(not main()))
