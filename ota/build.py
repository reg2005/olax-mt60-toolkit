#!/usr/bin/env python3
"""Reproducible kernel-only OTA builder. Does not connect to devices."""
import argparse,hashlib,io,json,os,subprocess,zipfile
from patch_boot import patch
from pathlib import Path
from ota_sign import sign,verify,check_recovery_key
ROOT=Path(__file__).resolve().parent
PINS={'installed/boot.img':'02b4337e75e0b088813b83280f93ef9fb908af96adcac5d1c0358884deba1feb','stock/boot.img':'aea6db447c55a144af61ad9d28bff920b294c7e7f30605ebc8938175c8f3278d','stock/recovery.img':'9a82a9dcb915efc78ce02e98c36fb45c82f087307882f7cb1585d8813b63ffc1'}
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--stock-boot',type=Path,required=True)
 parser.add_argument('--recovery',type=Path,required=True)
 parser.add_argument('--out',type=Path,required=True)
 args=parser.parse_args()
 OUT=args.out.resolve();BOOT=patch(args.stock_boot.read_bytes())
 if sha(args.recovery.read_bytes())!=PINS['stock/recovery.img']:raise ValueError('Recovery pin mismatch')
 for name,source in json.loads((ROOT/'vendor/sources.json').read_text()).items():
  if sha((ROOT/'vendor'/name).read_bytes())!=source['sha256']:raise ValueError('Vendor pin mismatch')
 check_recovery_key(args.recovery)
 build=ROOT/'build';build.mkdir(exist_ok=True)
 test_boot=build/'reviewed-test.img';test_boot.write_bytes(BOOT)
 subprocess.run(['go','test','./...'],cwd=ROOT,env=dict(os.environ,OLAX_TEST_BOOT=str(test_boot)),check=True)
 subprocess.run(['go','vet','./...'],cwd=ROOT,check=True)
 OUT.mkdir(parents=True,exist_ok=True);build=ROOT/'build';build.mkdir(exist_ok=True)
 records={}
 for mode,label in [('probe','01-CHECK-FIRST'),('install','02-KERNEL-UNLOCKED-ONLY')]:
  executable=build/('update-binary-'+mode)
  env=dict(os.environ,CGO_ENABLED='0',GOOS='linux',GOARCH='arm',GOARM='7')
  subprocess.run(['go','build','-trimpath','-buildvcs=false','-ldflags=-s -w -buildid= -X main.mode='+mode,'-o',str(executable),'.'],cwd=ROOT,env=env,check=True)
  elf=executable.read_bytes()
  if elf[:5]!=b'\x7fELF\x01' or int.from_bytes(elf[18:20],'little')!=40:raise ValueError('Expected ARM32 ELF')
  manifest={'product':'OLAX MT60 t60_extchg_k61','version':'0.1.0','experimental':True,'mode':mode,'requiresUnlockedBootloader':mode=='install','payloadSHA256':PINS['installed/boot.img'] if mode=='install' else None,'stockBootSHA256':PINS['stock/boot.img'],'recoverySHA256':PINS['stock/recovery.img'],'features':['Rfg CPU fix','internal CV cap4.35V'] if mode=='install' else ['read-only compatibility report'],'noAdmin':True,'noProxy':True,'noUnlock':True,'noWipe':True,'hardwareOTATested':False,'signing':'PUBLIC AOSP testkey; not an author identity signature'}
  raw=io.BytesIO()
  with zipfile.ZipFile(raw,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
   entries={'META-INF/com/google/android/update-binary':elf,'olax-manifest.json':json.dumps(manifest,indent=2).encode()}
   if mode=='install':entries['boot.img']=BOOT
   for name,content in entries.items():
    info=zipfile.ZipInfo(name,(2026,10,15,0,0,0));info.create_system=3;info.external_attr=(0o100755 if name.endswith('update-binary') else 0o100644)<<16;info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,content)
  signed=sign(raw.getvalue());verify(signed)
  name='OLAX-MT60-'+label+'-0.1.0.zip';(OUT/name).write_bytes(signed);records[name]={'sha256':sha(signed),'bytes':len(signed),'mode':mode,'hardwareTested':False}
 (OUT/'manifest.json').write_text(json.dumps(records,indent=2)+'\n')
 (OUT/'SHA256SUMS').write_text(''.join(f'{r["sha256"]}  {n}\n' for n,r in records.items()))
 for n,r in records.items():print(n,r['bytes'],r['sha256'])
if __name__=='__main__':main()
