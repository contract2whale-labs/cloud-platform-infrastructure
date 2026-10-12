import importlib.util
from pathlib import Path
import unittest

MODULE=Path(__file__).resolve().parents[2]/"automation/check_image_promotion.py"
spec=importlib.util.spec_from_file_location("promotion",MODULE)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)

class ImagePromotionTest(unittest.TestCase):
    def test_selected_digest_change(self):
        before={"images":[{"name":"app","newName":"repo/app","digest":"sha256:"+"a"*64}],"resources":["base"]}
        after={"resources":["base"],"images":[{"digest":"sha256:"+"b"*64,"newName":"repo/app","name":"app"}]}
        self.assertIsNone(mod.validate(before,after,"app","repo/app","sha256:"+"b"*64))
    def test_unrelated_change_rejected(self):
        before={"images":[{"name":"app","newName":"repo/app","digest":"sha256:"+"a"*64}],"resources":["base"]}
        after={"images":[{"name":"app","newName":"repo/app","digest":"sha256:"+"b"*64}],"resources":["unexpected"]}
        with self.assertRaises(ValueError):mod.validate(before,after,"app","repo/app","sha256:"+"b"*64)
