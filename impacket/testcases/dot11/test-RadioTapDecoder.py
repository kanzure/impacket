#!env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from ImpactDecoder import RadioTapDecoder
from binascii import hexlify
import unittest

class TestRadioTapDecoder(unittest.TestCase):

    def setUp(self):
        self.RadioTapData='\x00\x00\x20\x00\x67\x08\x04\x00\x30\x03\x1a\x25\x00\x00\x00\x00\x22\x0c\xd9\xa0\x02\x00\x00\x00\x40\x01\x00\x00\x3c\x14\x24\x11\x08\x02\x00\x00\xff\xff\xff\xff\xff\xff\x06\x03\x7f\x07\xa0\x16\x00\x19\xe3\xd3\x53\x52\x90\x7f\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x19\xe3\xd3\x53\x52\xa9\xfe\xf7\x00\x00\x00\x00\x00\x00\x00\x43\x08\x0e\x36'
        radiotap_decoder = RadioTapDecoder()
        self.in0=radiotap_decoder.decode(self.RadioTapData)        
        self.in1=self.in0.child()
        self.in2=self.in1.child()
        self.in3=self.in2.child()
        self.in4=self.in3.child()
        self.in5=self.in4.child()

    def test_00_RadioTapDecoder(self):
        'Test RadioTap decoder'
        self.assertEqual(str(self.in0.__class__), "dot11.RadioTap")
        
    def test_01_Dot11Decoder(self):
        'Test Dot11 decoder'
        self.assertEqual(str(self.in1.__class__), "dot11.Dot11")
        
    def test_02_Dot11DataFrameDecoder(self):
        'Test Dot11DataFrame decoder'
        self.assertEqual(str(self.in2.__class__), "dot11.Dot11DataFrame")
    
    def test_03_LLC(self):
        'Test LLC decoder'
        self.assertEqual(str(self.in3.__class__), "dot11.LLC")

    def test_04_Data(self):
        'Test SNAP decoder'
        self.assertEqual(str(self.in4.__class__), "dot11.SNAP")

    def test_05_Data(self):
        'Test Data decoder'
        self.assertEqual(str(self.in5.__class__), "ImpactPacket.Data")
      
suite = unittest.TestLoader().loadTestsFromTestCase(TestRadioTapDecoder)
unittest.TextTestRunner(verbosity=2).run(suite)

