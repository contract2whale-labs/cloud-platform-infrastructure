#!/usr/bin/env python3
"""Install official Linux amd64 release bytes from a reviewed SHA lock."""
import hashlib, json, os, shutil, subprocess, tarfile, tempfile, urllib.request, zipfile
from pathlib import Path

def main():
    lock=json.loads(Path('/opt/tooling/toolchain.lock.json').read_text())
    if lock['platform']!='linux/amd64':raise ValueError('unsupported architecture')
    with tempfile.TemporaryDirectory() as work:
        for record in lock['tools']:
            dest=Path(work)/record['name']
            with urllib.request.urlopen(record['url'],timeout=90) as response, dest.open('wb') as out:
                shutil.copyfileobj(response,out)
            if hashlib.sha256(dest.read_bytes()).hexdigest()!=record['sha256']:
                raise ValueError('release SHA differs from lock: '+record['name'])
            target=Path('/usr/local/bin')/record['binary']
            kind=record['archive']
            if kind=='raw':shutil.copyfile(dest,target)
            elif kind=='zip':
                with zipfile.ZipFile(dest) as z, z.open(record['member']) as source, target.open('wb') as out:shutil.copyfileobj(source,out)
            elif kind=='tar':
                with tarfile.open(dest) as t, t.extractfile(record['member']) as source, target.open('wb') as out:shutil.copyfileobj(source,out)
            elif kind=='deb':
                subprocess.run(['dpkg','--install',str(dest)],check=True)
            elif kind=='aws':
                awsdir=Path(work)/'aws-unpack';awsdir.mkdir()
                with zipfile.ZipFile(dest) as z:
                    for item in z.infolist():
                        if item.filename.startswith('/') or '..' in Path(item.filename).parts:raise ValueError('unsafe ZIP member')
                    z.extractall(awsdir)
                installer=awsdir/'aws/install';installer.chmod(0o755)
                for f in (awsdir/'aws/dist').rglob('*'):
                    if f.is_file() and (f.name=='aws' or f.read_bytes()[:4]==b'\x7fELF'):f.chmod(0o755)
                subprocess.run([str(installer),'--install-dir','/opt/aws-cli','--bin-dir','/usr/local/bin'],check=True)
            elif kind in {'go','node'}:
                # Official archive hash is fixed; tar itself preserves safe relative symlinks.
                with tarfile.open(dest) as t:
                    for item in t.getmembers():
                        if item.name.startswith('/') or '..' in Path(item.name).parts:raise ValueError('unsafe tar member')
                subprocess.run(['tar','-xf',str(dest),'-C','/opt'],check=True)
                source=Path('/opt/go/bin') if kind=='go' else Path('/opt/node-v'+record['version']+'-linux-x64/bin')
                for f in source.iterdir():
                    p=Path('/usr/local/bin')/f.name
                    if not p.exists():p.symlink_to(f)
            else:raise ValueError('unknown archive kind')
            if kind in {'raw','tar','zip'}:target.chmod(0o755)
            print('installed '+record['name']+' '+record['version'])

if __name__=='__main__':main()
