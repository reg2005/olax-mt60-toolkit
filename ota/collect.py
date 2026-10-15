#!/usr/bin/env python3
"""Read-only OTA diagnostic collector; explicit ADB serial, no auto discovery."""
import argparse,json,os,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--serial',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
if a.out.exists():p.error('Output exists; choose a new private report path')
commands={
 'model':['getprop','ro.product.model'],
 'device':['getprop','ro.product.device'],
 'locked':['getprop','ro.boot.flash.locked'],
 'verified':['getprop','ro.boot.verifiedbootstate'],
 'bootSHA':['sha256sum','/dev/block/platform/bootdevice/by-name/boot'],
 'lastRecoveryLog':['tail','-c','262144','/cache/recovery/last_log'],
 'currentRecoveryLog':['tail','-c','262144','/cache/recovery/log'],
}
report={}
for name,args in commands.items():
 r=subprocess.run(['adb','-s',a.serial,'shell',*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25)
 report[name]={'exit':r.returncode,'text':r.stdout[:262144].decode(errors='replace')}
a.out.parent.mkdir(parents=True,exist_ok=True)
fd=os.open(a.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as f:json.dump(report,f,indent=2,ensure_ascii=False)
print('Private diagnostic report saved:',a.out)
