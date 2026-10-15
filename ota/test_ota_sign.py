import io,unittest,zipfile,subprocess
import ota_sign
class SigningTests(unittest.TestCase):
 def sample(self):
  out=io.BytesIO()
  with zipfile.ZipFile(out,'w') as z:z.writestr('payload','test payload')
  return ota_sign.sign(out.getvalue())
 def test_valid(self):self.assertTrue(ota_sign.verify(self.sample()))
 def test_changed_payload(self):
  raw=bytearray(self.sample());raw[38]^=1
  with self.assertRaises((ValueError,subprocess.CalledProcessError,zipfile.BadZipFile)):ota_sign.verify(bytes(raw))
 def test_changed_footer(self):
  raw=bytearray(self.sample());raw[-3]=0
  with self.assertRaises(ValueError):ota_sign.verify(bytes(raw))
 def test_truncated(self):
  with self.assertRaises(ValueError):ota_sign.verify(self.sample()[:-10])
 def test_unsigned(self):
  with self.assertRaises(ValueError):ota_sign.verify(b'not a signed zip')
 def test_signature_changed(self):
  raw=bytearray(self.sample());raw[-15]^=1
  with self.assertRaises(subprocess.CalledProcessError):ota_sign.verify(bytes(raw))
if __name__=='__main__':unittest.main()
