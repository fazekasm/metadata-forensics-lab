"""Build on the target OS; PyInstaller does not cross-compile."""
import pathlib, platform, subprocess, sys, shutil
ROOT = pathlib.Path(__file__).resolve().parent

def main():
    command = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--windowed', '--name', 'Metadata Forensics Lab']
    for module in ('webview', 'fitz', 'pymupdf'):
        command += ['--collect-all', module]
    for module in ('uvicorn.logging', 'uvicorn.loops.auto', 'uvicorn.protocols.http.auto', 'uvicorn.lifespan.on', 'forensic_extensions', 'wayback_extensions'):
        command += ['--hidden-import', module]
    command += ['mac_desktop.py']
    subprocess.run(command, cwd=ROOT, check=True)
    system = platform.system().lower()
    target = ROOT / 'dist' / ('Metadata Forensics Lab.app' if system == 'darwin' else 'Metadata Forensics Lab')
    packages = ROOT / 'packages'
    packages.mkdir(exist_ok=True)
    name = str(packages / f'metadata-forensics-lab-{system}-{platform.machine()}')
    if system == 'darwin':
        subprocess.run(['ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', str(target), name + '.zip'], check=True)
    else:
        shutil.make_archive(name, 'zip' if system == 'windows' else 'gztar', root_dir=target.parent, base_dir=target.name)
    print('Unsigned package created. Test on the target OS before distribution.')

if __name__ == '__main__':
    main()
