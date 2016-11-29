# bochs-instrument
Instrument for the bochs emulator.

## mbr
In order to use this instrument, you have to change some code in cpu/cpu.cc to
 pass EIP, as last parameter.

That's why it's ugly, but I didn't find a better way yet.
